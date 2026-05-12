"""Packet parsing module."""

import gc
import os
import re
import subprocess
from pathlib import Path
from typing import Iterable, Iterator, Optional

import pyshark

from core.models import PacketInfo, Protocol
from utils.config import get_config
from utils.logger import setup_logger

logger = setup_logger()


class PcapParser:
    def __init__(
        self,
        file_path: str,
        batch_size: int = 10000,
        display_filter: Optional[str] = None,
    ):
        self.file_path = Path(file_path)
        self.batch_size = batch_size
        self.display_filter = str(display_filter or "").strip() or None
        self.total_packets = 0
        self._tshark_payload_map: dict[int, str] = {}
        self._tshark_payload_missing: set[int] = set()
        self._tshark_payload_full_loaded = False
        self._tshark_payload_full_failed = False
        self._tshark_payload_query_count = 0
        self._tshark_payload_lookup_window = 24
        self._tshark_payload_full_threshold = 72
        self._tshark_payload_field_sets = [
            ["frame.number", "tcp.len", "tcp.segment_data", "tcp.reassembled.data", "data.data"],
            ["frame.number", "tcp.len", "tcp.segment_data", "data.data"],
            ["frame.number", "tcp.len", "data.data"],
        ]
        try:
            payload_backfill_cfg = get_config().get("analysis.tcp_payload_backfill.enabled", False)
        except Exception:
            payload_backfill_cfg = False
        self._payload_backfill_enabled = self._as_bool(payload_backfill_cfg)

    @staticmethod
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def parse(self, max_packets: Optional[int] = None) -> Iterator[PacketInfo]:
        """Parse pcap file and yield normalized packets."""
        logger.info(f"Start parsing file: {self.file_path}")

        cap = None
        try:
            tshark_path = os.environ.get("TSHARK_PATH")
            capture_kwargs = {"keep_packets": False}
            if self.display_filter:
                capture_kwargs["display_filter"] = self.display_filter
            if tshark_path:
                cap = pyshark.FileCapture(
                    str(self.file_path),
                    **capture_kwargs,
                    tshark_path=tshark_path,
                )
            else:
                cap = pyshark.FileCapture(str(self.file_path), **capture_kwargs)

            for packet in cap:
                try:
                    packet_info = self._extract_packet_info(packet)
                    if not packet_info:
                        continue

                    self.total_packets += 1
                    yield packet_info

                    # Large-file memory protection.
                    if self.total_packets % self.batch_size == 0:
                        gc.collect()

                    if max_packets and self.total_packets >= max_packets:
                        logger.info(f"Reached max packet limit: {max_packets}")
                        break
                except Exception as exc:
                    logger.debug(f"Failed to parse packet #{self.total_packets}: {exc}")
                    continue

            logger.info(f"Parse complete, packets: {self.total_packets}")
        except Exception as exc:
            logger.error(f"File parse failed: {exc}")
            raise
        finally:
            if cap is not None:
                try:
                    cap.close()
                except Exception:
                    pass

    @staticmethod
    def _normalize_payload_hex(raw_value) -> str:
        """Normalize tshark/pyshark payload field text to plain hex bytes."""
        if raw_value is None:
            return ""

        text = str(raw_value).strip()
        if not text:
            return ""

        candidates = []
        # Typical tshark bytes form: aa:bb:cc...
        candidates.extend(re.findall(r"(?:[0-9A-Fa-f]{2}:){1,}[0-9A-Fa-f]{2}", text))
        # Alternate bytes form: aa bb cc...
        candidates.extend(re.findall(r"(?:[0-9A-Fa-f]{2}\s+){1,}[0-9A-Fa-f]{2}", text))
        # Plain hex blob.
        candidates.extend(re.findall(r"\b[0-9A-Fa-f]{8,}\b", text))

        if not candidates:
            return ""

        best = max(candidates, key=len)
        cleaned = "".join(ch for ch in best if ch in "0123456789abcdefABCDEF").lower()
        if len(cleaned) % 2 != 0:
            cleaned = cleaned[:-1]
        return cleaned

    @staticmethod
    def _layer_field_value(layer, field_name: str):
        if layer is None:
            return None
        try:
            value = layer.get_field(field_name)
            if value is not None and str(value).strip():
                return value
        except Exception:
            pass
        return None

    def _extract_tcp_payload_hex(self, packet) -> str:
        """
        Extract TCP payload bytes in a tshark-version-compatible way.
        Newer tshark versions may expose payload as `tcp.segment_data`
        or `data.data` rather than `tcp.payload`.
        """
        tcp_layer = getattr(packet, "tcp", None)
        if tcp_layer is not None:
            for attr in ("payload", "segment_data", "reassembled_data"):
                payload_hex = self._normalize_payload_hex(getattr(tcp_layer, attr, None))
                if payload_hex:
                    return payload_hex

            for field_name in ("tcp.payload", "tcp.segment_data", "tcp.reassembled.data"):
                payload_hex = self._normalize_payload_hex(self._layer_field_value(tcp_layer, field_name))
                if payload_hex:
                    return payload_hex

        data_layer = getattr(packet, "data", None)
        if data_layer is not None:
            for attr in ("data", "data_data"):
                payload_hex = self._normalize_payload_hex(getattr(data_layer, attr, None))
                if payload_hex:
                    return payload_hex

            payload_hex = self._normalize_payload_hex(self._layer_field_value(data_layer, "data.data"))
            if payload_hex:
                return payload_hex

        # Some captures expose multiple data layers.
        for layer in getattr(packet, "layers", []) or []:
            if str(getattr(layer, "layer_name", "")).lower() != "data":
                continue
            for attr in ("data", "data_data"):
                payload_hex = self._normalize_payload_hex(getattr(layer, attr, None))
                if payload_hex:
                    return payload_hex
            payload_hex = self._normalize_payload_hex(self._layer_field_value(layer, "data.data"))
            if payload_hex:
                return payload_hex

        return ""

    def _stream_payload_map_from_tshark(
        self,
        tshark_path: str,
        fields: list[str],
        frame_numbers: Optional[Iterable[int]] = None,
    ) -> Optional[dict[int, str]]:
        """Build frame_no -> payload_hex map from tshark fields output."""
        display_filter = "tcp.len>0"
        if frame_numbers is not None:
            normalized = sorted(
                {
                    int(num)
                    for num in frame_numbers
                    if int(num) > 0
                }
            )
            if normalized:
                expr = " or ".join(f"frame.number=={num}" for num in normalized)
                display_filter = f"tcp.len>0 && ({expr})"
        cmd = [
            tshark_path,
            "-r",
            str(self.file_path),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-E",
            "header=n",
            "-E",
            "separator=/t",
        ]
        for field in fields:
            cmd.extend(["-e", field])

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except Exception as exc:
            logger.debug(f"Failed to start tshark payload query: {exc}")
            return None

        payload_map: dict[int, str] = {}
        try:
            if proc.stdout is not None:
                for line in proc.stdout:
                    row = line.rstrip("\r\n")
                    if not row:
                        continue
                    cols = row.split("\t")
                    if len(cols) < 2:
                        continue
                    try:
                        frame_no = int(str(cols[0]).strip())
                    except Exception:
                        continue
                    try:
                        tcp_len = int(str(cols[1]).strip() or "0")
                    except Exception:
                        tcp_len = 0
                    if tcp_len <= 0:
                        continue

                    best_payload = ""
                    for raw_value in cols[2:]:
                        candidate = self._normalize_payload_hex(raw_value)
                        if candidate and len(candidate) > len(best_payload):
                            best_payload = candidate

                    if best_payload:
                        payload_map[frame_no] = best_payload

            stderr_text = ""
            if proc.stderr is not None:
                stderr_text = proc.stderr.read()
            rc = proc.wait()
            if rc != 0:
                err_preview = (stderr_text or "").strip().splitlines()
                preview = err_preview[0] if err_preview else f"exit={rc}"
                logger.debug(f"tshark payload query failed ({preview})")
                return None
            return payload_map
        finally:
            try:
                if proc.stdout is not None:
                    proc.stdout.close()
            except Exception:
                pass
            try:
                if proc.stderr is not None:
                    proc.stderr.close()
            except Exception:
                pass

    def _query_tshark_payload_for_frames(self, frame_numbers: Iterable[int]) -> int:
        """
        Query payload bytes for selected frames only.
        Returns number of newly-resolved frames.
        """
        pending = sorted(
            {
                int(num)
                for num in frame_numbers
                if int(num) > 0
                and int(num) not in self._tshark_payload_map
                and int(num) not in self._tshark_payload_missing
            }
        )
        if not pending:
            return 0

        tshark_path = os.environ.get("TSHARK_PATH") or "tshark"
        resolved: Optional[dict[int, str]] = None
        used_fields = ""
        for fields in self._tshark_payload_field_sets:
            payload_map = self._stream_payload_map_from_tshark(
                tshark_path,
                fields,
                frame_numbers=pending,
            )
            if payload_map is None:
                continue
            resolved = payload_map
            used_fields = ",".join(fields)
            break

        if resolved is None:
            return 0

        if resolved:
            self._tshark_payload_map.update(resolved)
        unresolved = [num for num in pending if num not in self._tshark_payload_map]
        self._tshark_payload_missing.update(unresolved)
        if resolved:
            logger.debug(
                "Loaded tshark payload subset: +%s frames (requested=%s, fields=%s)",
                len(resolved),
                len(pending),
                used_fields,
            )
        return len(resolved)

    def _ensure_tshark_payload_map(self):
        """Fallback: load full payload map after repeated misses."""
        if self._tshark_payload_full_loaded or self._tshark_payload_full_failed:
            return

        tshark_path = os.environ.get("TSHARK_PATH") or "tshark"
        for fields in self._tshark_payload_field_sets:
            payload_map = self._stream_payload_map_from_tshark(tshark_path, fields)
            if payload_map is None:
                continue
            self._tshark_payload_map.update(payload_map)
            self._tshark_payload_full_loaded = True
            logger.info(
                "Loaded tshark payload map: %s frames (fields=%s)",
                len(payload_map),
                ",".join(fields),
            )
            return

        self._tshark_payload_full_failed = True

    def _payload_from_tshark_map(self, packet_number: int) -> str:
        pkt_no = int(packet_number)
        cached = self._tshark_payload_map.get(pkt_no, "")
        if cached:
            return cached
        if pkt_no in self._tshark_payload_missing:
            return ""

        self._tshark_payload_query_count += 1
        if self._tshark_payload_query_count >= self._tshark_payload_full_threshold:
            self._ensure_tshark_payload_map()
            if pkt_no in self._tshark_payload_map:
                return self._tshark_payload_map[pkt_no]
            self._tshark_payload_missing.add(pkt_no)
            return ""

        start = max(pkt_no, 1)
        end = start + max(self._tshark_payload_lookup_window, 1)
        self._query_tshark_payload_for_frames(range(start, end))
        if pkt_no in self._tshark_payload_map:
            return self._tshark_payload_map[pkt_no]

        self._tshark_payload_missing.add(pkt_no)
        return ""

    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract PacketInfo from a pyshark packet."""
        try:
            info = PacketInfo(
                number=int(packet.number),
                timestamp=float(packet.sniff_timestamp),
                length=int(packet.length),
                protocol=Protocol.OTHER,
                transport_protocol=Protocol.OTHER,
                application_protocol=None,
            )

            # IPv4
            if hasattr(packet, "ip"):
                info.src_ip = getattr(packet.ip, "src", None)
                info.dst_ip = getattr(packet.ip, "dst", None)
                try:
                    if hasattr(packet.ip, "hdr_len"):
                        info.ip_header_len = int(str(packet.ip.hdr_len), 0)
                    info.ip_flags = str(packet.ip.flags)
                    info.ip_frag_offset = int(packet.ip.frag_offset)
                    info.ip_id = int(packet.ip.id, 16) if hasattr(packet.ip, "id") else None
                    info.ip_ttl = int(packet.ip.ttl)
                    info.ip_total_len = int(packet.ip.len)
                    if hasattr(packet.ip, "options"):
                        info.ip_options = str(packet.ip.options)
                except Exception:
                    pass
            # IPv6 (basic support)
            elif hasattr(packet, "ipv6"):
                info.src_ip = getattr(packet.ipv6, "src", None)
                info.dst_ip = getattr(packet.ipv6, "dst", None)
                try:
                    info.ip_header_len = 40
                    if hasattr(packet.ipv6, "hlim"):
                        info.ip_ttl = int(packet.ipv6.hlim)
                    if hasattr(packet.ipv6, "plen"):
                        # ipv6 payload length + fixed header length
                        info.ip_total_len = int(packet.ipv6.plen) + 40
                except Exception:
                    pass

            # Transport layer
            if hasattr(packet, "tcp"):
                info.transport_protocol = Protocol.TCP
                info.protocol = Protocol.TCP
                info.src_port = int(packet.tcp.srcport)
                info.dst_port = int(packet.tcp.dstport)
                info.tcp_flags = str(packet.tcp.flags)
                if hasattr(packet.tcp, "seq"):
                    info.tcp_seq = int(packet.tcp.seq)
                if hasattr(packet.tcp, "ack"):
                    info.tcp_ack = int(packet.tcp.ack)
                if hasattr(packet.tcp, "stream"):
                    try:
                        info.tcp_stream_id = int(str(packet.tcp.stream), 0)
                    except Exception:
                        pass
                payload_hex = self._extract_tcp_payload_hex(packet)
                if payload_hex:
                    info.tcp_payload_hex = payload_hex
                try:
                    if hasattr(packet.tcp, "hdr_len"):
                        info.tcp_header_len = int(str(packet.tcp.hdr_len), 0)
                    if hasattr(packet.tcp, "window_size_value"):
                        info.tcp_window = int(packet.tcp.window_size_value)
                    if hasattr(packet.tcp, "len"):
                        info.tcp_payload_len = int(packet.tcp.len)
                    elif info.tcp_payload_hex:
                        info.tcp_payload_len = len(info.tcp_payload_hex) // 2
                except Exception:
                    pass
                if (
                    self._payload_backfill_enabled
                    and not info.tcp_payload_hex
                    and int(info.tcp_payload_len or 0) > 0
                ):
                    payload_hex = self._payload_from_tshark_map(int(packet.number))
                    if payload_hex:
                        info.tcp_payload_hex = payload_hex
                        if not info.tcp_payload_len:
                            info.tcp_payload_len = len(payload_hex) // 2

                try:
                    analysis = str(packet.tcp.analysis) if hasattr(packet.tcp, "analysis") else ""
                    if analysis:
                        info.expert_info = analysis
                    if hasattr(packet.tcp, "analysis_retransmission"):
                        info.is_retransmission = True
                    if hasattr(packet.tcp, "analysis_fast_retransmission"):
                        info.is_fast_retrans = True
                    if hasattr(packet.tcp, "analysis_duplicate_ack"):
                        info.is_dup_ack = True
                    if hasattr(packet.tcp, "analysis_zero_window"):
                        info.is_zero_window = True
                    if hasattr(packet.tcp, "analysis_window_full"):
                        info.is_window_full = True
                    if hasattr(packet.tcp, "analysis_ack_rtt"):
                        info.tcp_rtt = float(packet.tcp.analysis_ack_rtt)
                except Exception:
                    pass
            elif hasattr(packet, "udp"):
                info.transport_protocol = Protocol.UDP
                info.protocol = Protocol.UDP
                info.src_port = int(packet.udp.srcport)
                info.dst_port = int(packet.udp.dstport)
            elif hasattr(packet, "icmp") or hasattr(packet, "icmpv6"):
                info.transport_protocol = Protocol.ICMP
                info.protocol = Protocol.ICMP
                try:
                    if hasattr(packet, "icmp"):
                        info.icmp_type = int(packet.icmp.type)
                        info.icmp_code = int(packet.icmp.code)
                    else:
                        # icmpv6 fields in pyshark vary by version
                        icmpv6_layer = packet.icmpv6
                        if hasattr(icmpv6_layer, "type"):
                            info.icmp_type = int(icmpv6_layer.type)
                        if hasattr(icmpv6_layer, "code"):
                            info.icmp_code = int(icmpv6_layer.code)
                except Exception:
                    pass
            elif hasattr(packet, "arp"):
                info.transport_protocol = Protocol.ARP
                info.protocol = Protocol.ARP
                try:
                    arp_layer = packet.arp
                    if hasattr(arp_layer, "opcode"):
                        info.arp_opcode = int(str(arp_layer.opcode), 0)

                    # Prefer ARP-layer addresses when IP layer does not exist.
                    info.arp_src_ip = getattr(arp_layer, "src_proto_ipv4", None) or getattr(
                        arp_layer, "src_proto_ipv6", None
                    )
                    info.arp_dst_ip = getattr(arp_layer, "dst_proto_ipv4", None) or getattr(
                        arp_layer, "dst_proto_ipv6", None
                    )
                    info.arp_src_mac = getattr(arp_layer, "src_hw_mac", None)
                    info.arp_dst_mac = getattr(arp_layer, "dst_hw_mac", None)

                    if not info.src_ip and info.arp_src_ip:
                        info.src_ip = str(info.arp_src_ip)
                    if not info.dst_ip and info.arp_dst_ip:
                        info.dst_ip = str(info.arp_dst_ip)
                except Exception:
                    pass

            # Application layer (do not overwrite transport protocol)
            if hasattr(packet, "dns"):
                info.application_protocol = Protocol.DNS
                try:
                    if hasattr(packet.dns, "id"):
                        info.dns_id = int(str(packet.dns.id), 0)
                    if hasattr(packet.dns, "flags_response"):
                        value = str(packet.dns.flags_response).strip().lower()
                        info.dns_is_response = value in {"1", "true", "yes"}
                    if hasattr(packet.dns, "time"):
                        info.dns_response_time = float(packet.dns.time)
                    if hasattr(packet.dns, "rcode"):
                        info.dns_rcode = int(packet.dns.rcode)
                except Exception:
                    pass

            if hasattr(packet, "http"):
                info.application_protocol = Protocol.HTTP
                try:
                    if hasattr(packet.http, "request_method"):
                        info.http_is_request = True
                    if hasattr(packet.http, "response_code"):
                        info.http_is_response = True
                        info.http_status = int(packet.http.response_code)
                    if hasattr(packet.http, "time"):
                        info.http_response_time = float(packet.http.time)
                except Exception:
                    pass

            if hasattr(packet, "tls") or hasattr(packet, "ssl"):
                info.application_protocol = Protocol.TLS
                try:
                    tls_layer = packet.tls if hasattr(packet, "tls") else packet.ssl
                    if hasattr(tls_layer, "alert_message"):
                        info.tls_alert_desc = str(tls_layer.alert_message)
                    elif hasattr(tls_layer, "alert_description"):
                        info.tls_alert_desc = str(tls_layer.alert_description)
                except Exception:
                    pass

            return info
        except Exception as exc:
            logger.debug(f"Failed to extract packet info: {exc}")
            return None

    def get_file_info(self) -> dict:
        """Get basic file metadata."""
        size = self.file_path.stat().st_size
        return {
            "path": str(self.file_path),
            "name": self.file_path.name,
            "size": size,
            "size_mb": size / 1024 / 1024,
        }
