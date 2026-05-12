"""Metrics extraction module."""

import statistics
import string
import zlib
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from core.models import PacketInfo, Protocol, TCPSession
from utils.config import get_config


class FlowAnalysis:
    """Bidirectional flow/session aggregation."""

    def __init__(
        self,
        flow_key: str,
        protocol: Protocol,
        endpoint_a_ip: str,
        endpoint_a_port: int,
        endpoint_b_ip: str,
        endpoint_b_port: int,
    ):
        self.flow_key = flow_key
        self.protocol = protocol

        self.endpoint_a_ip = endpoint_a_ip
        self.endpoint_a_port = endpoint_a_port
        self.endpoint_b_ip = endpoint_b_ip
        self.endpoint_b_port = endpoint_b_port

        self.client_endpoint: Optional[Tuple[str, int]] = None
        self.server_endpoint: Optional[Tuple[str, int]] = None

        self.packets: List[PacketInfo] = []
        self.packets_a_to_b = 0
        self.packets_b_to_a = 0
        self.bytes_a_to_b = 0
        self.bytes_b_to_a = 0

        self.syn_count = 0
        self.syn_ack_count = 0
        self.ack_count = 0
        self.final_ack_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.retrans_count = 0
        self.fast_retrans_count = 0
        self.dup_ack_count = 0
        self.zero_window_count = 0
        self.window_full_count = 0
        self.out_of_order_count = 0
        self.rtts: List[float] = []
        self.handshake_complete = False
        self.connection_reset = False
        self.syn_time: Optional[float] = None
        self.syn_ack_time: Optional[float] = None
        self.final_ack_time: Optional[float] = None
        self.handshake_synack_ms: Optional[float] = None
        self.handshake_ack_ms: Optional[float] = None
        self.quick_disconnect: bool = False
        self.http_request_times: List[float] = []
        self.http_response_times: List[float] = []
        self.http_latencies: List[float] = []
        self.first_packet_time = None
        self.last_packet_time = None
        self.total_bytes = 0
        self.issues: List[str] = []
        self.frag_issues: List[str] = []
        self.length_anomalies: List[str] = []
        self.max_gap: float = 0.0


class MetricsExtractor:
    def __init__(self):
        self.packets: List[PacketInfo] = []
        self.flows: Dict[Tuple[Any, ...], FlowAnalysis] = {}
        self.tcp_sessions: Dict[str, TCPSession] = {}

    @staticmethod
    def _transport_protocol(packet: PacketInfo) -> Protocol:
        return packet.transport_protocol or packet.protocol

    @staticmethod
    def _application_protocol(packet: PacketInfo) -> Optional[Protocol]:
        return packet.application_protocol

    @staticmethod
    def _endpoint_tuple(ip: str, port: Optional[int]) -> Tuple[str, int]:
        if port is None:
            return (ip, -1)
        try:
            return (ip, int(port))
        except Exception:
            return (ip, -1)

    @classmethod
    def _build_bidir_flow_key(cls, packet: PacketInfo, protocol: Protocol) -> Tuple[Any, ...]:
        ep1 = cls._endpoint_tuple(packet.src_ip or "", packet.src_port)
        ep2 = cls._endpoint_tuple(packet.dst_ip or "", packet.dst_port)
        if protocol == Protocol.ICMP:
            icmp_type = int(packet.icmp_type) if packet.icmp_type is not None else -1
            icmp_code = int(packet.icmp_code) if packet.icmp_code is not None else -1
            if ep1 <= ep2:
                return (protocol.value, icmp_type, icmp_code, ep1[0], ep1[1], ep2[0], ep2[1])
            return (protocol.value, icmp_type, icmp_code, ep2[0], ep2[1], ep1[0], ep1[1])
        if protocol == Protocol.ARP:
            arp_opcode = int(packet.arp_opcode) if packet.arp_opcode is not None else -1
            arp_src = packet.arp_src_ip or packet.src_ip or ""
            arp_dst = packet.arp_dst_ip or packet.dst_ip or ""
            if ep1 <= ep2:
                return (protocol.value, arp_opcode, arp_src, arp_dst, ep1[0], ep1[1], ep2[0], ep2[1])
            return (protocol.value, arp_opcode, arp_dst, arp_src, ep2[0], ep2[1], ep1[0], ep1[1])
        if ep1 <= ep2:
            return (protocol.value, ep1[0], ep1[1], ep2[0], ep2[1])
        return (protocol.value, ep2[0], ep2[1], ep1[0], ep1[1])

    @staticmethod
    def _flow_display_key(flow: FlowAnalysis) -> str:
        return (
            f"{flow.endpoint_a_ip}:{flow.endpoint_a_port}"
            f"<->{flow.endpoint_b_ip}:{flow.endpoint_b_port}"
        )

    @staticmethod
    def _is_tcp_flag_set(flags: Optional[str], flag: str) -> bool:
        if not flags:
            return False

        text = str(flags).upper()

        # Support hex-form flags (e.g. 0x0012 from tshark)
        if text.startswith("0X"):
            try:
                value = int(text, 16)
                bit_map = {
                    "F": 0x01,
                    "S": 0x02,
                    "R": 0x04,
                    "P": 0x08,
                    "A": 0x10,
                    "U": 0x20,
                    "E": 0x40,
                    "C": 0x80,
                }
                return bool(value & bit_map.get(flag, 0))
            except Exception:
                pass

        return flag in text

    @classmethod
    def _tcp_payload_len(cls, packet: PacketInfo) -> int:
        try:
            if packet.tcp_payload_len is not None:
                value = int(packet.tcp_payload_len)
                if value >= 0:
                    return value
        except Exception:
            pass
        payload_hex = cls._clean_hex(packet.tcp_payload_hex)
        if payload_hex:
            return len(payload_hex) // 2
        return 0

    @classmethod
    def _retrans_signature(cls, packet: PacketInfo) -> Optional[Tuple[int, int, str]]:
        """
        Build retransmission signature.
        - Data segment: (seq, payload_len, "DATA")
        - Control segment (SYN/FIN/RST): (seq, 0, "<flags>")
        Pure ACK packets are ignored to avoid false retransmission counts.
        """
        if packet.tcp_seq is None:
            return None

        payload_len = cls._tcp_payload_len(packet)
        if payload_len > 0:
            return (int(packet.tcp_seq), int(payload_len), "DATA")

        has_syn = cls._is_tcp_flag_set(packet.tcp_flags, "S")
        has_fin = cls._is_tcp_flag_set(packet.tcp_flags, "F")
        has_rst = cls._is_tcp_flag_set(packet.tcp_flags, "R")
        if not (has_syn or has_fin or has_rst):
            return None

        marker = (
            ("S" if has_syn else "")
            + ("F" if has_fin else "")
            + ("R" if has_rst else "")
        )
        return (int(packet.tcp_seq), 0, marker or "CTRL")

    @classmethod
    def _is_retransmission_event(cls, packet: PacketInfo, seen_signatures: set) -> bool:
        """
        Unified retransmission detection used by flow/window/timeline statistics.
        Prefer tshark expert flag, otherwise infer by repeated segment signature.
        """
        signature = cls._retrans_signature(packet)
        if packet.is_retransmission:
            if signature is not None:
                seen_signatures.add(signature)
            return True

        if signature is None:
            return False
        if signature in seen_signatures:
            return True
        seen_signatures.add(signature)
        return False

    @staticmethod
    def _clean_hex(payload_hex: Optional[str]) -> str:
        if not payload_hex:
            return ""
        text = str(payload_hex).replace(":", "").strip()
        if not text:
            return ""
        filtered = "".join(ch for ch in text if ch in string.hexdigits)
        if len(filtered) % 2 != 0:
            filtered = filtered[:-1]
        return filtered.lower()

    @classmethod
    def _payload_bytes(cls, packet: PacketInfo) -> bytes:
        payload_hex = cls._clean_hex(packet.tcp_payload_hex)
        if not payload_hex:
            return b""
        try:
            return bytes.fromhex(payload_hex)
        except Exception:
            return b""

    @staticmethod
    def _safe_ascii_preview(data: bytes, char_limit: int = 1200) -> str:
        if not data:
            return ""
        text = data.decode("utf-8", errors="replace")
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        mapped_chars: List[str] = []
        for ch in normalized:
            code = ord(ch)
            if ch in "\n\t":
                mapped_chars.append(ch)
            elif 32 <= code <= 126:
                mapped_chars.append(ch)
            else:
                mapped_chars.append(".")
            if len(mapped_chars) >= char_limit:
                mapped_chars.append("\n... (truncated)")
                break
        return "".join(mapped_chars).strip()

    @staticmethod
    def _hex_preview(data: bytes, byte_limit: int = 320) -> str:
        if not data:
            return ""
        sliced = data[: max(byte_limit, 1)]
        hex_pairs = sliced.hex()
        grouped = " ".join(hex_pairs[i : i + 2] for i in range(0, len(hex_pairs), 2))
        if len(data) > len(sliced):
            grouped += " ..."
        return grouped

    @classmethod
    def _stream_group_key(cls, packet: PacketInfo) -> str:
        if packet.tcp_stream_id is not None:
            return f"stream:{int(packet.tcp_stream_id)}"
        ep1 = cls._endpoint_tuple(packet.src_ip or "", packet.src_port)
        ep2 = cls._endpoint_tuple(packet.dst_ip or "", packet.dst_port)
        if ep1 <= ep2:
            return f"flow:{ep1[0]}:{ep1[1]}<->{ep2[0]}:{ep2[1]}"
        return f"flow:{ep2[0]}:{ep2[1]}<->{ep1[0]}:{ep1[1]}"

    @classmethod
    def _reassemble_segments(
        cls,
        segments: List[Dict[str, Any]],
        max_bytes: int,
    ) -> Dict[str, Any]:
        if not segments or max_bytes <= 0:
            return {"data": b"", "used_segments": 0, "dropped_segments": 0}

        sorted_segments = sorted(
            segments,
            key=lambda seg: (
                int(seg.get("seq", 0) or 0),
                float(seg.get("timestamp", 0.0) or 0.0),
                int(seg.get("packet_no", 0) or 0),
            ),
        )

        assembled = bytearray()
        seen = set()
        cursor: Optional[int] = None
        used_segments = 0
        dropped_segments = 0

        for seg in sorted_segments:
            payload = seg.get("payload") or b""
            if not payload:
                continue

            seq = int(seg.get("seq", 0) or 0)
            key = (seq, len(payload), payload[:24])
            if key in seen:
                dropped_segments += 1
                continue
            seen.add(key)

            if cursor is None:
                take = min(len(payload), max_bytes - len(assembled))
                if take <= 0:
                    break
                assembled.extend(payload[:take])
                cursor = seq + len(payload)
                used_segments += 1
                continue

            if seq >= cursor:
                take = min(len(payload), max_bytes - len(assembled))
                if take <= 0:
                    break
                assembled.extend(payload[:take])
                cursor = seq + len(payload)
                used_segments += 1
                continue

            overlap = cursor - seq
            if overlap >= len(payload):
                dropped_segments += 1
                continue

            tail = payload[overlap:]
            take = min(len(tail), max_bytes - len(assembled))
            if take <= 0:
                break
            assembled.extend(tail[:take])
            cursor += len(tail)
            used_segments += 1

        return {
            "data": bytes(assembled),
            "used_segments": used_segments,
            "dropped_segments": dropped_segments,
        }

    def _packet_direction(self, flow: FlowAnalysis, packet: PacketInfo) -> int:
        if (
            packet.src_ip == flow.endpoint_a_ip
            and int(packet.src_port or 0) == flow.endpoint_a_port
            and packet.dst_ip == flow.endpoint_b_ip
            and int(packet.dst_port or 0) == flow.endpoint_b_port
        ):
            return 0
        return 1

    def add_packet(self, packet: PacketInfo):
        """Add one packet to metrics state."""
        self.packets.append(packet)

        transport = self._transport_protocol(packet)
        if transport not in {Protocol.TCP, Protocol.UDP}:
            return
        if not packet.src_ip or not packet.dst_ip:
            return

        key = self._build_bidir_flow_key(packet, transport)
        if key not in self.flows:
            _, a_ip, a_port, b_ip, b_port = key
            flow = FlowAnalysis(
                flow_key=f"{a_ip}:{a_port}<->{b_ip}:{b_port}",
                protocol=transport,
                endpoint_a_ip=a_ip,
                endpoint_a_port=a_port,
                endpoint_b_ip=b_ip,
                endpoint_b_port=b_port,
            )
            self.flows[key] = flow

        flow = self.flows[key]
        flow.packets.append(packet)
        flow.total_bytes += packet.length

        direction = self._packet_direction(flow, packet)
        if direction == 0:
            flow.packets_a_to_b += 1
            flow.bytes_a_to_b += packet.length
        else:
            flow.packets_b_to_a += 1
            flow.bytes_b_to_a += packet.length

        if flow.first_packet_time is None:
            flow.first_packet_time = packet.timestamp
        flow.last_packet_time = packet.timestamp

        if transport != Protocol.TCP:
            return
        if not packet.tcp_flags:
            return

        has_syn = self._is_tcp_flag_set(packet.tcp_flags, "S")
        has_ack = self._is_tcp_flag_set(packet.tcp_flags, "A")
        has_rst = self._is_tcp_flag_set(packet.tcp_flags, "R")
        has_fin = self._is_tcp_flag_set(packet.tcp_flags, "F")

        if has_syn and not has_ack:
            flow.syn_count += 1
            if flow.syn_time is None:
                flow.syn_time = packet.timestamp
            # First SYN without ACK identifies initiator.
            if flow.client_endpoint is None:
                flow.client_endpoint = (packet.src_ip, int(packet.src_port or 0))
                flow.server_endpoint = (packet.dst_ip, int(packet.dst_port or 0))
        elif has_syn and has_ack:
            flow.syn_ack_count += 1
            if flow.syn_ack_time is None:
                flow.syn_ack_time = packet.timestamp

        if has_ack:
            flow.ack_count += 1
            if (
                not has_syn
                and flow.client_endpoint is not None
                and flow.server_endpoint is not None
                and (packet.src_ip, int(packet.src_port or 0)) == flow.client_endpoint
                and (packet.dst_ip, int(packet.dst_port or 0)) == flow.server_endpoint
                and flow.syn_ack_count > 0
            ):
                flow.final_ack_count += 1
                flow.handshake_complete = True
                if flow.final_ack_time is None:
                    flow.final_ack_time = packet.timestamp

        if has_rst:
            flow.rst_count += 1
            flow.connection_reset = True
        if has_fin:
            flow.fin_count += 1

        # HTTP request/response timing hints (per TCP flow).
        if self._application_protocol(packet) == Protocol.HTTP:
            if packet.http_is_request:
                flow.http_request_times.append(packet.timestamp)
            if packet.http_is_response:
                flow.http_response_times.append(packet.timestamp)
                if packet.http_response_time and packet.http_response_time > 0:
                    flow.http_latencies.append(float(packet.http_response_time))

    def _build_packet_buckets(self) -> Dict[str, Any]:
        """
        Build one-pass packet buckets to avoid repeated full-list scans.
        This improves large-file extraction performance.
        """
        transport_counts: Dict[str, int] = defaultdict(int)
        app_counts: Dict[str, int] = defaultdict(int)
        src_ips: Dict[str, int] = defaultdict(int)
        dst_ips: Dict[str, int] = defaultdict(int)
        dst_ports: Dict[int, int] = defaultdict(int)
        send_bytes: Dict[str, int] = defaultdict(int)
        recv_bytes: Dict[str, int] = defaultdict(int)

        tcp_packets: List[PacketInfo] = []
        udp_packets: List[PacketInfo] = []
        icmp_packets: List[PacketInfo] = []
        arp_packets: List[PacketInfo] = []
        timestamps: List[float] = []

        for packet in self.packets:
            timestamps.append(float(packet.timestamp))

            transport = self._transport_protocol(packet)
            transport_counts[transport.value] += 1

            app = self._application_protocol(packet)
            if app:
                app_counts[app.value] += 1

            if packet.src_ip:
                src_ips[packet.src_ip] += 1
                send_bytes[packet.src_ip] += int(packet.length or 0)
            if packet.dst_ip:
                dst_ips[packet.dst_ip] += 1
                recv_bytes[packet.dst_ip] += int(packet.length or 0)
            if packet.dst_port is not None:
                dst_ports[int(packet.dst_port)] += 1

            if transport == Protocol.TCP:
                tcp_packets.append(packet)
            elif transport == Protocol.UDP:
                udp_packets.append(packet)
            elif transport == Protocol.ICMP:
                icmp_packets.append(packet)
            elif transport == Protocol.ARP:
                arp_packets.append(packet)

        return {
            "packets": self.packets,
            "timestamps": timestamps,
            "transport_counts": dict(transport_counts),
            "app_counts": dict(app_counts),
            "src_ips": src_ips,
            "dst_ips": dst_ips,
            "dst_ports": dst_ports,
            "send_bytes": send_bytes,
            "recv_bytes": recv_bytes,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "icmp_packets": icmp_packets,
            "arp_packets": arp_packets,
        }

    def extract_all_metrics(self) -> Dict[str, Any]:
        """Extract all metrics."""
        self._analyze_flow_issues()
        packet_buckets = self._build_packet_buckets()

        basic = self._extract_basic_stats(packet_buckets)
        protocol_stats = self._extract_transport_protocol_stats(packet_buckets)
        app_protocol_stats = self._extract_application_protocol_stats(packet_buckets)
        tcp_metrics = self._extract_tcp_metrics(packet_buckets)
        performance = self._extract_performance_metrics(packet_buckets)
        top_talkers = self._extract_top_talkers(packet_buckets)
        flow_analysis = self._extract_flow_analysis()
        problem_flows = self._extract_problem_flows()
        network_metrics = self._extract_network_metrics(basic, packet_buckets)
        udp_metrics = self._extract_udp_metrics(packet_buckets)
        app_metrics = self._extract_application_metrics(packet_buckets)
        time_baseline = self._extract_time_baseline(basic, packet_buckets)
        traffic_timeline = self._extract_traffic_timeline(basic, packet_buckets)
        ip_topology = self._extract_ip_topology(packet_buckets)
        # Follow Stream output was removed from reports; keep key for compatibility.
        tcp_streams: Dict[str, Any] = {}
        cfg_thresholds = get_config().get("analysis.thresholds", {}) or {}

        return {
            "basic": basic,
            "protocol": protocol_stats,
            "application_protocol": app_protocol_stats,
            "tcp": tcp_metrics,
            "performance": performance,
            "top_talkers": top_talkers,
            "flow_analysis": flow_analysis,
            "problem_flows": problem_flows,
            "network": network_metrics,
            "udp": udp_metrics,
            "application": app_metrics,
            "time_baseline": time_baseline,
            "traffic_timeline": traffic_timeline,
            "ip_topology": ip_topology,
            "tcp_streams": tcp_streams,
            "config_thresholds": cfg_thresholds,
        }

    def _analyze_flow_issues(self):
        """Analyze per-flow issues."""
        for flow in self.flows.values():
            if flow.protocol != Protocol.TCP:
                if flow.protocol == Protocol.UDP:
                    if min(flow.packets_a_to_b, flow.packets_b_to_a) == 0 and len(flow.packets) >= 3:
                        flow.issues.append("UDP无响应：仅单向流量且未见ICMP错误")
                continue

            if flow.syn_count > 0 and flow.syn_ack_count == 0:
                flow.issues.append("握手失败：SYN无响应")
            if flow.syn_ack_count > 0 and flow.final_ack_count == 0:
                flow.issues.append("握手失败：收到SYN-ACK后未见ACK")
            if flow.rst_count > 0:
                flow.issues.append(f"连接被重置（RST包数：{flow.rst_count}）")
            if min(flow.packets_a_to_b, flow.packets_b_to_a) == 0 and len(flow.packets) > 3:
                flow.issues.append("单向流量：无回包")

            cfg = get_config().get("analysis.thresholds", {}) or {}
            synack_high_ms = float(cfg.get("handshake_synack_high_ms", 300))
            ack_high_ms = float(cfg.get("handshake_ack_high_ms", 300))
            quick_disconnect_s = float(cfg.get("quick_disconnect_s", 2.0))
            connection_leak_s = float(cfg.get("connection_leak_duration_s", 120.0))
            connection_leak_min_packets = int(cfg.get("connection_leak_min_packets", 30))

            seq_seen = {0: set(), 1: set()}
            for pkt in flow.packets:
                direction = self._packet_direction(flow, pkt)
                if self._is_retransmission_event(pkt, seq_seen[direction]):
                    flow.retrans_count += 1

                if pkt.is_fast_retrans:
                    flow.fast_retrans_count += 1
                if pkt.is_dup_ack:
                    flow.dup_ack_count += 1
                if pkt.is_zero_window:
                    flow.zero_window_count += 1
                if pkt.is_window_full:
                    flow.window_full_count += 1
                if pkt.expert_info and "out-of-order" in pkt.expert_info.lower():
                    flow.out_of_order_count += 1
                if pkt.tcp_rtt:
                    flow.rtts.append(pkt.tcp_rtt)

            if flow.syn_time is not None and flow.syn_ack_time is not None and flow.syn_ack_time >= flow.syn_time:
                flow.handshake_synack_ms = (flow.syn_ack_time - flow.syn_time) * 1000
                if flow.handshake_synack_ms > synack_high_ms:
                    flow.issues.append(
                        f"握手时延异常：SYN->SYN-ACK {flow.handshake_synack_ms:.1f}ms"
                    )
            if (
                flow.syn_ack_time is not None
                and flow.final_ack_time is not None
                and flow.final_ack_time >= flow.syn_ack_time
            ):
                flow.handshake_ack_ms = (flow.final_ack_time - flow.syn_ack_time) * 1000
                if flow.handshake_ack_ms > ack_high_ms:
                    flow.issues.append(
                        f"握手时延异常：SYN-ACK->ACK {flow.handshake_ack_ms:.1f}ms"
                    )

            if flow.retrans_count > 0:
                flow.issues.append(f"重传异常（重传包数：{flow.retrans_count}）")
            if flow.fast_retrans_count > 0:
                flow.issues.append(f"快速重传：{flow.fast_retrans_count} 次")
            if flow.dup_ack_count >= 3:
                flow.issues.append(f"重复ACK：{flow.dup_ack_count} 次，疑似丢包")
            if flow.zero_window_count > 0:
                flow.issues.append(f"TCP Zero Window：{flow.zero_window_count} 次，接收端窗口耗尽")
            if flow.window_full_count > 0:
                flow.issues.append(f"TCP Window Full：{flow.window_full_count} 次，发送端受限")
            if flow.out_of_order_count > 3:
                flow.issues.append(f"乱序报文：{flow.out_of_order_count} 个，路径可能抖动")

            times = [p.timestamp for p in flow.packets]
            if len(times) >= 2:
                gaps = [times[i + 1] - times[i] for i in range(len(times) - 1)]
                flow.max_gap = max(gaps)
                if flow.max_gap > 3.0:
                    flow.issues.append(f"流内卡顿（最大包间隔{flow.max_gap:.2f}秒）")

            # Pair HTTP request/response timestamps as latency fallback.
            if flow.http_request_times and flow.http_response_times:
                req_idx = 0
                rsp_idx = 0
                req_times = sorted(flow.http_request_times)
                rsp_times = sorted(flow.http_response_times)
                while req_idx < len(req_times) and rsp_idx < len(rsp_times):
                    if rsp_times[rsp_idx] >= req_times[req_idx]:
                        delta = rsp_times[rsp_idx] - req_times[req_idx]
                        if 0 < delta <= 120:
                            flow.http_latencies.append(delta)
                        req_idx += 1
                        rsp_idx += 1
                    else:
                        rsp_idx += 1

            if (
                flow.handshake_complete
                and flow.final_ack_time is not None
                and flow.last_packet_time is not None
                and (flow.rst_count > 0 or flow.fin_count > 0)
            ):
                post_handshake_alive = flow.last_packet_time - flow.final_ack_time
                if post_handshake_alive <= quick_disconnect_s and flow.total_bytes < 64 * 1024:
                    flow.quick_disconnect = True
                    flow.issues.append(
                        f"握手后快速断开：{post_handshake_alive:.2f}s内出现FIN/RST，疑似应用拒绝或策略拦截"
                    )

            if (
                flow.handshake_complete
                and flow.first_packet_time is not None
                and flow.last_packet_time is not None
                and flow.fin_count == 0
                and flow.rst_count == 0
                and len(flow.packets) >= connection_leak_min_packets
            ):
                alive_s = float(flow.last_packet_time) - float(flow.first_packet_time)
                if alive_s >= connection_leak_s:
                    flow.issues.append(
                        f"连接疑似泄漏：已持续 {alive_s:.1f}s 且未见 FIN/RST 关闭"
                    )

            self._analyze_frag_issues(flow)
            self._analyze_length_anomalies(flow)

    def _analyze_frag_issues(self, flow: FlowAnalysis):
        """Detect IP fragmentation anomalies."""
        frag_groups: Dict[int, List[PacketInfo]] = defaultdict(list)
        for pkt in flow.packets:
            if pkt.ip_id is None or pkt.ip_frag_offset is None:
                continue
            is_mf = bool(
                pkt.ip_flags
                and (
                    "0x1" in pkt.ip_flags
                    or "MF" in pkt.ip_flags
                    or str(pkt.ip_flags).endswith("1")
                )
            )
            if is_mf or pkt.ip_frag_offset > 0:
                frag_groups[pkt.ip_id].append(pkt)

        for ip_id, frags in frag_groups.items():
            offsets = sorted(set(p.ip_frag_offset for p in frags if p.ip_frag_offset is not None))
            if len(offsets) > 1:
                for i in range(1, len(offsets)):
                    prev_pkt = next((p for p in frags if p.ip_frag_offset == offsets[i - 1]), None)
                    if prev_pkt is None:
                        continue
                    ip_header_len = (
                        prev_pkt.ip_header_len
                        if prev_pkt.ip_header_len is not None
                        else (40 if (prev_pkt.src_ip and ":" in prev_pkt.src_ip) else 20)
                    )
                    prev_ip_len = (
                        prev_pkt.ip_total_len if prev_pkt.ip_total_len is not None else prev_pkt.length
                    )
                    expected = offsets[i - 1] + max((prev_ip_len - ip_header_len) // 8, 0)
                    if offsets[i] > expected + 2:
                        flow.frag_issues.append(
                            f"分片重组异常：IP_ID=0x{ip_id:04x} 偏移不连续 {offsets[i-1]}->{offsets[i]}，期望≈{expected}"
                        )
                        flow.issues.append(f"IP分片重组异常（IP_ID=0x{ip_id:04x}）")
                        break

            for pkt in frags:
                if pkt.ip_total_len is None:
                    continue
                is_last = not (
                    pkt.ip_flags
                    and ("MF" in str(pkt.ip_flags) or str(pkt.ip_flags).endswith("1"))
                )
                ip_header_len = 40 if (pkt.src_ip and ":" in pkt.src_ip) else 20
                payload_len = pkt.ip_total_len - ip_header_len
                if not is_last and payload_len > 0 and payload_len % 8 != 0:
                    flow.frag_issues.append(
                        f"分片长度错误：IP_ID=0x{ip_id:04x} 载荷长度{payload_len}不是8的倍数"
                    )
                    flow.issues.append(f"IP分片长度不正确（IP_ID=0x{ip_id:04x}）")

    @staticmethod
    def _is_normal_l2_overhead(overhead: int) -> bool:
        """Whether frame length - IP total length is a common link-layer overhead."""
        if overhead == 0:
            return True
        if overhead < 0 or overhead > 64:
            return False
        # Common Ethernet/SLL overheads:
        #   14/18 bytes base (without/with FCS), +4 per VLAN tag.
        return ((overhead - 14) % 4 == 0) or ((overhead - 18) % 4 == 0) or overhead in {16, 20}

    def _analyze_length_anomalies(self, flow: FlowAnalysis):
        """Detect packet length anomalies while excluding normal L2 overhead."""
        for pkt in flow.packets:
            if pkt.ip_total_len and pkt.length:
                l2_overhead = pkt.length - pkt.ip_total_len
                if not self._is_normal_l2_overhead(l2_overhead):
                    flow.length_anomalies.append(
                        f"包#{pkt.number} 长度关系异常：IP声明{pkt.ip_total_len}B，帧长{pkt.length}B，L2开销{l2_overhead}B"
                    )
                    if "数据包长度异常" not in flow.issues:
                        flow.issues.append("数据包长度异常（IP长度与链路层帧长关系异常）")

            # Use real header lengths (including TCP options) to avoid false positives.
            is_ipv4 = ":" not in (pkt.src_ip or "") and ":" not in (pkt.dst_ip or "")
            if (
                is_ipv4
                and self._transport_protocol(pkt) == Protocol.TCP
                and pkt.ip_total_len is not None
                and pkt.ip_header_len is not None
                and pkt.tcp_header_len is not None
                and pkt.tcp_payload_len is not None
            ):
                expected_payload = pkt.ip_total_len - pkt.ip_header_len - pkt.tcp_header_len
                if expected_payload >= 0 and abs(pkt.tcp_payload_len - expected_payload) > 4:
                    flow.length_anomalies.append(
                        f"包#{pkt.number} TCP载荷长度异常：期望≈{expected_payload}B，实际{pkt.tcp_payload_len}B"
                    )
                    if "TCP载荷长度异常" not in flow.issues:
                        flow.issues.append("TCP载荷长度异常（IP头长与TCP头长不匹配）")

    def _extract_flow_analysis(self) -> Dict[str, Any]:
        return {
            "total_flows": len(self.flows),
            "flows_with_issues": sum(1 for f in self.flows.values() if f.issues),
            "flows": {
                v.flow_key: {
                    "protocol": v.protocol.value,
                    "packets": len(v.packets),
                    "issues": v.issues,
                    "handshake_complete": v.handshake_complete,
                    "connection_reset": v.connection_reset,
                    "syn_count": v.syn_count,
                    "syn_ack_count": v.syn_ack_count,
                    "ack_count": v.ack_count,
                    "final_ack_count": v.final_ack_count,
                    "rst_count": v.rst_count,
                    "fin_count": v.fin_count,
                    "retrans_count": v.retrans_count,
                    "fast_retrans_count": v.fast_retrans_count,
                    "dup_ack_count": v.dup_ack_count,
                    "zero_window_count": v.zero_window_count,
                    "window_full_count": v.window_full_count,
                    "out_of_order_count": v.out_of_order_count,
                    "max_gap": v.max_gap,
                    "frag_issues": v.frag_issues,
                    "length_anomalies": v.length_anomalies,
                    "packets_a_to_b": v.packets_a_to_b,
                    "packets_b_to_a": v.packets_b_to_a,
                    "handshake_synack_ms": v.handshake_synack_ms,
                    "handshake_ack_ms": v.handshake_ack_ms,
                    "quick_disconnect": v.quick_disconnect,
                    "duration_s": (
                        float(v.last_packet_time) - float(v.first_packet_time)
                        if v.first_packet_time is not None and v.last_packet_time is not None
                        else 0.0
                    ),
                    "http_latency_count": len(v.http_latencies),
                }
                for v in self.flows.values()
            },
        }

    def _extract_problem_flows(self) -> List[Dict[str, Any]]:
        problem_flows = []
        for flow in self.flows.values():
            if not flow.issues:
                continue

            if flow.client_endpoint and flow.server_endpoint:
                src_ip, src_port = flow.client_endpoint
                dst_ip, dst_port = flow.server_endpoint
            else:
                src_ip, src_port = flow.endpoint_a_ip, flow.endpoint_a_port
                dst_ip, dst_port = flow.endpoint_b_ip, flow.endpoint_b_port

            packet_numbers = [
                int(pkt.number)
                for pkt in flow.packets
                if getattr(pkt, "number", None) is not None
            ]
            first_packet_no = min(packet_numbers) if packet_numbers else 0
            last_packet_no = max(packet_numbers) if packet_numbers else 0
            evidence_seed = (
                f"{src_ip}:{int(src_port)}->{dst_ip}:{int(dst_port)}"
                f"#{first_packet_no}-{last_packet_no}|{len(flow.packets)}"
            )
            evidence_id = f"EV-{zlib.crc32(evidence_seed.encode('utf-8')) & 0xFFFFFFFF:08X}"

            problem_flows.append(
                {
                    "src_ip": src_ip,
                    "src_port": int(src_port),
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port),
                    "issues": flow.issues,
                    "protocol": flow.protocol.value,
                    "packet_count": len(flow.packets),
                    "syn_count": flow.syn_count,
                    "syn_ack_count": flow.syn_ack_count,
                    "ack_count": flow.ack_count,
                    "final_ack_count": flow.final_ack_count,
                    "rst_count": flow.rst_count,
                    "fin_count": flow.fin_count,
                    "retrans_count": flow.retrans_count,
                    "fast_retrans_count": flow.fast_retrans_count,
                    "dup_ack_count": flow.dup_ack_count,
                    "out_of_order_count": flow.out_of_order_count,
                    "zero_window_count": flow.zero_window_count,
                    "window_full_count": flow.window_full_count,
                    "max_gap": flow.max_gap,
                    "duration_s": (
                        float(flow.last_packet_time) - float(flow.first_packet_time)
                        if flow.first_packet_time is not None and flow.last_packet_time is not None
                        else 0.0
                    ),
                    "frag_issues": flow.frag_issues,
                    "length_anomalies": flow.length_anomalies,
                    "total_bytes": flow.total_bytes,
                    "packets_a_to_b": flow.packets_a_to_b,
                    "packets_b_to_a": flow.packets_b_to_a,
                    "handshake_synack_ms": flow.handshake_synack_ms,
                    "handshake_ack_ms": flow.handshake_ack_ms,
                    "quick_disconnect": flow.quick_disconnect,
                    "http_latency_samples": len(flow.http_latencies),
                    "http_latency_avg_ms": (statistics.mean(flow.http_latencies) * 1000)
                    if flow.http_latencies
                    else 0.0,
                    "rtt_avg_ms": (statistics.mean(flow.rtts) * 1000) if flow.rtts else 0.0,
                    "rtt_p95_ms": (self._percentile(flow.rtts, 0.95) * 1000) if flow.rtts else 0.0,
                    "rtt_max_ms": (max(flow.rtts) * 1000) if flow.rtts else 0.0,
                    "first_packet_no": first_packet_no,
                    "last_packet_no": last_packet_no,
                    "evidence_id": evidence_id,
                }
            )
        return problem_flows

    def _extract_basic_stats(self, buckets: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        packets = (buckets or {}).get("packets", self.packets)
        if not packets:
            return {}

        timestamps = list((buckets or {}).get("timestamps") or [p.timestamp for p in packets])
        return {
            "total_packets": len(packets),
            "start_time": min(timestamps),
            "end_time": max(timestamps),
            "duration": max(timestamps) - min(timestamps),
            "total_bytes": sum(int(p.length or 0) for p in packets),
        }

    def _extract_transport_protocol_stats(self, buckets: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
        if buckets and "transport_counts" in buckets:
            return dict(buckets.get("transport_counts") or {})
        stats = defaultdict(int)
        for packet in self.packets:
            stats[self._transport_protocol(packet).value] += 1
        return dict(stats)

    def _extract_application_protocol_stats(self, buckets: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
        if buckets and "app_counts" in buckets:
            return dict(buckets.get("app_counts") or {})
        stats = defaultdict(int)
        for packet in self.packets:
            app = self._application_protocol(packet)
            if app:
                stats[app.value] += 1
        return dict(stats)

    def _extract_tcp_metrics(self, buckets: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        tcp_packets = list((buckets or {}).get("tcp_packets") or [])
        if not tcp_packets:
            tcp_packets = [p for p in self.packets if self._transport_protocol(p) == Protocol.TCP]
        if not tcp_packets:
            return {}

        syn_count = sum(
            1
            for p in tcp_packets
            if self._is_tcp_flag_set(p.tcp_flags, "S") and not self._is_tcp_flag_set(p.tcp_flags, "A")
        )
        syn_ack_count = sum(
            1
            for p in tcp_packets
            if self._is_tcp_flag_set(p.tcp_flags, "S") and self._is_tcp_flag_set(p.tcp_flags, "A")
        )
        rst_count = sum(1 for p in tcp_packets if self._is_tcp_flag_set(p.tcp_flags, "R"))
        fin_count = sum(1 for p in tcp_packets if self._is_tcp_flag_set(p.tcp_flags, "F"))
        ack_count = sum(1 for p in tcp_packets if self._is_tcp_flag_set(p.tcp_flags, "A"))

        # Use flow-level retransmission count for consistency with per-flow analysis.
        retrans_count = sum(f.retrans_count for f in self.flows.values() if f.protocol == Protocol.TCP)
        fast_retrans_count = sum(1 for p in tcp_packets if p.is_fast_retrans)
        dup_ack_count = sum(1 for p in tcp_packets if p.is_dup_ack)
        zero_window_count = sum(1 for p in tcp_packets if p.is_zero_window)
        window_full_count = sum(1 for p in tcp_packets if p.is_window_full)
        rtts = [p.tcp_rtt for p in tcp_packets if p.tcp_rtt]
        max_rtt = max(rtts) if rtts else 0
        avg_rtt = statistics.mean(rtts) if rtts else 0
        rtt_p95 = self._percentile(rtts, 0.95) if rtts else 0
        rtt_cv = (statistics.pstdev(rtts) / avg_rtt) if len(rtts) > 1 and avg_rtt > 0 else 0

        tcp_flows = [f for f in self.flows.values() if f.protocol == Protocol.TCP]
        connection_attempts = sum(1 for f in tcp_flows if int(f.syn_count or 0) > 0)
        connection_failures = sum(
            1
            for f in tcp_flows
            if (
                (int(f.syn_count or 0) > 0 and int(f.syn_ack_count or 0) == 0)
                or (int(f.syn_ack_count or 0) > 0 and int(f.final_ack_count or 0) == 0)
            )
        )
        connection_successes = max(connection_attempts - connection_failures, 0)
        connection_success_rate = (
            connection_successes / connection_attempts if connection_attempts > 0 else 0.0
        )
        zero_win_flows = sum(1 for f in tcp_flows if f.zero_window_count > 0)
        window_full_flows = sum(1 for f in tcp_flows if f.window_full_count > 0)
        slow_flows = sum(1 for f in tcp_flows if f.max_gap > 3.0)
        frag_issue_flows = sum(1 for f in tcp_flows if f.frag_issues)
        length_issue_flows = sum(1 for f in tcp_flows if f.length_anomalies)
        quick_disconnect_flows = sum(1 for f in tcp_flows if f.quick_disconnect)
        connection_leak_flows = sum(
            1 for f in tcp_flows if any("连接疑似泄漏" in issue for issue in (f.issues or []))
        )
        half_open_flows = sum(
            1 for f in tcp_flows if f.syn_ack_count > 0 and f.final_ack_count == 0 and len(f.packets) <= 3
        )
        out_of_order_flows = sum(1 for f in tcp_flows if f.out_of_order_count > 3)

        synack_samples = [f.handshake_synack_ms for f in tcp_flows if f.handshake_synack_ms is not None]
        ack_samples = [f.handshake_ack_ms for f in tcp_flows if f.handshake_ack_ms is not None]

        return {
            "total_tcp": len(tcp_packets),
            "syn": syn_count,
            "syn_ack": syn_ack_count,
            "rst": rst_count,
            "fin": fin_count,
            "ack": ack_count,
            "retransmissions": retrans_count,
            "retrans_rate": retrans_count / len(tcp_packets) if tcp_packets else 0,
            "rst_rate": rst_count / len(tcp_packets) if tcp_packets else 0,
            "fast_retrans": fast_retrans_count,
            "dup_ack": dup_ack_count,
            "zero_window": zero_window_count,
            "window_full": window_full_count,
            "window_full_rate": window_full_count / len(tcp_packets) if tcp_packets else 0,
            "zero_win_flows": zero_win_flows,
            "window_full_flows": window_full_flows,
            "total_tcp_flows": len(tcp_flows),
            "total_sessions": len(tcp_flows),
            "connection_attempts": connection_attempts,
            "connection_failures": connection_failures,
            "connection_successes": connection_successes,
            "connection_success_rate": connection_success_rate,
            "slow_flows": slow_flows,
            "frag_issue_flows": frag_issue_flows,
            "length_issue_flows": length_issue_flows,
            "quick_disconnect_flows": quick_disconnect_flows,
            "connection_leak_flows": connection_leak_flows,
            "max_rtt": max_rtt,
            "avg_rtt": avg_rtt,
            "rtt_p95": rtt_p95,
            "rtt_jitter_cv": rtt_cv,
            "half_open_flows": half_open_flows,
            "out_of_order_flows": out_of_order_flows,
            "handshake_synack_avg_ms": statistics.mean(synack_samples) if synack_samples else 0,
            "handshake_synack_p95_ms": self._percentile(synack_samples, 0.95) if synack_samples else 0,
            "handshake_ack_avg_ms": statistics.mean(ack_samples) if ack_samples else 0,
            "handshake_ack_p95_ms": self._percentile(ack_samples, 0.95) if ack_samples else 0,
        }

    def _detect_retransmissions(self, tcp_packets: List[PacketInfo]) -> int:
        seq_map = defaultdict(set)
        retrans = 0

        for packet in tcp_packets:
            if not packet.src_ip or not packet.dst_ip:
                continue
            key = (
                packet.src_ip,
                int(packet.src_port or 0),
                packet.dst_ip,
                int(packet.dst_port or 0),
            )
            if self._is_retransmission_event(packet, seq_map[key]):
                retrans += 1

        return retrans

    def _extract_performance_metrics(self, buckets: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        timestamps = list((buckets or {}).get("timestamps") or [p.timestamp for p in self.packets])
        if len(timestamps) < 2:
            return {}

        intervals = []
        for i in range(1, len(timestamps)):
            interval = float(timestamps[i]) - float(timestamps[i - 1])
            intervals.append(interval)

        return {
            "avg_interval": statistics.mean(intervals) if intervals else 0,
            "max_interval": max(intervals) if intervals else 0,
            "min_interval": min(intervals) if intervals else 0,
        }

    @staticmethod
    def _percentile(values: List[float], p: float) -> float:
        if not values:
            return 0.0
        if len(values) == 1:
            return float(values[0])
        seq = sorted(float(v) for v in values)
        idx = (len(seq) - 1) * max(0.0, min(1.0, p))
        lo = int(idx)
        hi = min(lo + 1, len(seq) - 1)
        if lo == hi:
            return float(seq[lo])
        frac = idx - lo
        return float(seq[lo] * (1 - frac) + seq[hi] * frac)

    def _extract_time_baseline(self, basic: Dict[str, Any], buckets: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Learn per-time-window baseline for dynamic thresholding."""
        packets = list((buckets or {}).get("packets") or self.packets)
        if not packets:
            return {}

        cfg = get_config()
        dyn_cfg = cfg.get("analysis.dynamic_threshold", {}) or {}
        window_seconds = float(dyn_cfg.get("window_seconds", 10))
        min_window_packets = int(dyn_cfg.get("min_window_packets", 20))
        if window_seconds <= 0:
            window_seconds = 10.0

        start_time = basic.get("start_time")
        if start_time is None:
            return {}

        windows: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {
                "total_packets": 0,
                "tcp_packets": 0,
                "total_bytes": 0,
                "retransmissions": 0,
                "rst": 0,
                "rtts": [],
                "timestamps": [],
            }
        )

        seq_seen: Dict[Tuple[int, str, int, str, int], set] = defaultdict(set)

        for packet in packets:
            idx = int((packet.timestamp - start_time) // window_seconds)
            win = windows[idx]
            win["total_packets"] += 1
            win["total_bytes"] += int(packet.length or 0)
            win["timestamps"].append(packet.timestamp)

            if self._transport_protocol(packet) != Protocol.TCP:
                continue
            win["tcp_packets"] += 1

            if self._is_tcp_flag_set(packet.tcp_flags, "R"):
                win["rst"] += 1

            if packet.tcp_rtt:
                win["rtts"].append(packet.tcp_rtt)

            if packet.src_ip and packet.dst_ip:
                key = (
                    idx,
                    packet.src_ip,
                    int(packet.src_port or 0),
                    packet.dst_ip,
                    int(packet.dst_port or 0),
                )
                if self._is_retransmission_event(packet, seq_seen[key]):
                    win["retransmissions"] += 1

        if not windows:
            return {}

        window_rows: List[Dict[str, Any]] = []
        for idx in sorted(windows.keys()):
            win = windows[idx]
            tcp_packets = int(win["tcp_packets"] or 0)
            if tcp_packets <= 0:
                continue
            ts = sorted(win["timestamps"])
            max_gap = 0.0
            if len(ts) >= 2:
                max_gap = max(ts[i + 1] - ts[i] for i in range(len(ts) - 1))
            row = {
                "index": idx,
                "start_offset_s": round(idx * window_seconds, 3),
                "end_offset_s": round((idx + 1) * window_seconds, 3),
                "total_packets": int(win["total_packets"] or 0),
                "tcp_packets": tcp_packets,
                "total_bytes": int(win["total_bytes"] or 0),
                "throughput_bps": (float(win["total_bytes"] or 0) * 8.0 / window_seconds),
                "retransmissions": int(win["retransmissions"] or 0),
                "rst": int(win["rst"] or 0),
                "retrans_rate": (float(win["retransmissions"] or 0) / max(tcp_packets, 1)),
                "rst_rate": (float(win["rst"] or 0) / max(tcp_packets, 1)),
                "avg_rtt_ms": (statistics.mean(win["rtts"]) * 1000) if win["rtts"] else 0.0,
                "max_gap_s": float(max_gap),
            }
            window_rows.append(row)

        active_rows = [row for row in window_rows if int(row["tcp_packets"]) >= min_window_packets]
        if not active_rows:
            active_rows = window_rows
        if not active_rows:
            return {}

        retrans_rates = [float(row["retrans_rate"]) for row in active_rows]
        rst_rates = [float(row["rst_rate"]) for row in active_rows]
        rtt_ms_values = [float(row["avg_rtt_ms"]) for row in active_rows if float(row["avg_rtt_ms"]) > 0]
        max_gap_values = [float(row["max_gap_s"]) for row in active_rows]
        throughput_values = [float(row["throughput_bps"]) for row in active_rows if float(row["throughput_bps"]) > 0]

        retrans_mean = statistics.mean(retrans_rates) if retrans_rates else 0.0
        retrans_std = statistics.pstdev(retrans_rates) if len(retrans_rates) > 1 else 0.0
        rst_mean = statistics.mean(rst_rates) if rst_rates else 0.0
        rst_std = statistics.pstdev(rst_rates) if len(rst_rates) > 1 else 0.0
        rtt_mean = statistics.mean(rtt_ms_values) if rtt_ms_values else 0.0
        rtt_std = statistics.pstdev(rtt_ms_values) if len(rtt_ms_values) > 1 else 0.0
        max_gap_mean = statistics.mean(max_gap_values) if max_gap_values else 0.0
        max_gap_std = statistics.pstdev(max_gap_values) if len(max_gap_values) > 1 else 0.0
        throughput_mean = statistics.mean(throughput_values) if throughput_values else 0.0
        throughput_std = statistics.pstdev(throughput_values) if len(throughput_values) > 1 else 0.0

        retrans_p95 = self._percentile(retrans_rates, 0.95)
        rst_p95 = self._percentile(rst_rates, 0.95)
        rtt_p95 = self._percentile(rtt_ms_values, 0.95)
        max_gap_p95 = self._percentile(max_gap_values, 0.95)
        throughput_p95 = self._percentile(throughput_values, 0.95)

        retrans_spike_th = retrans_mean + max(2 * retrans_std, 0.01)
        rst_spike_th = rst_mean + max(2 * rst_std, 0.005)
        spike_windows = [
            row
            for row in active_rows
            if float(row["retrans_rate"]) > retrans_spike_th or float(row["rst_rate"]) > rst_spike_th
        ]
        spike_windows = sorted(
            spike_windows,
            key=lambda row: float(row["retrans_rate"]) * 2 + float(row["rst_rate"]) * 3,
            reverse=True,
        )[:8]

        rtt_jitter_cv = (rtt_std / rtt_mean) if rtt_mean > 0 else 0.0
        throughput_jitter_cv = (throughput_std / throughput_mean) if throughput_mean > 0 else 0.0

        return {
            "window_seconds": window_seconds,
            "min_window_packets": min_window_packets,
            "window_count": len(window_rows),
            "active_window_count": len(active_rows),
            "retrans_rate_mean": retrans_mean,
            "retrans_rate_std": retrans_std,
            "retrans_rate_p95": retrans_p95,
            "rst_rate_mean": rst_mean,
            "rst_rate_std": rst_std,
            "rst_rate_p95": rst_p95,
            "avg_rtt_ms_mean": rtt_mean,
            "avg_rtt_ms_std": rtt_std,
            "avg_rtt_ms_p95": rtt_p95,
            "rtt_jitter_cv": rtt_jitter_cv,
            "max_gap_s_mean": max_gap_mean,
            "max_gap_s_std": max_gap_std,
            "max_gap_s_p95": max_gap_p95,
            "throughput_bps_mean": throughput_mean,
            "throughput_bps_std": throughput_std,
            "throughput_bps_p95": throughput_p95,
            "throughput_jitter_cv": throughput_jitter_cv,
            "spike_windows": [
                {
                    "index": row["index"],
                    "start_offset_s": row["start_offset_s"],
                    "end_offset_s": row["end_offset_s"],
                    "retrans_rate": row["retrans_rate"],
                    "rst_rate": row["rst_rate"],
                    "avg_rtt_ms": row["avg_rtt_ms"],
                    "throughput_bps": row["throughput_bps"],
                }
                for row in spike_windows
            ],
        }

    def _extract_top_talkers(
        self,
        buckets: Optional[Dict[str, Any]] = None,
        top_n: int = 10,
    ) -> Dict[str, Any]:
        src_ips = (buckets or {}).get("src_ips")
        dst_ips = (buckets or {}).get("dst_ips")
        dst_ports = (buckets or {}).get("dst_ports")
        if src_ips is None or dst_ips is None or dst_ports is None:
            src_ips = defaultdict(int)
            dst_ips = defaultdict(int)
            dst_ports = defaultdict(int)

            for packet in self.packets:
                if packet.src_ip:
                    src_ips[packet.src_ip] += 1
                if packet.dst_ip:
                    dst_ips[packet.dst_ip] += 1
                if packet.dst_port is not None:
                    dst_ports[int(packet.dst_port)] += 1

        return {
            "top_src_ips": dict(sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:top_n]),
            "top_dst_ips": dict(sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:top_n]),
            "top_dst_ports": dict(sorted(dst_ports.items(), key=lambda x: x[1], reverse=True)[:top_n]),
        }

    def _extract_network_metrics(
        self,
        basic: Dict[str, Any],
        buckets: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        packets = list((buckets or {}).get("packets") or self.packets)
        icmp_packets = list((buckets or {}).get("icmp_packets") or [])
        arp_packets = list((buckets or {}).get("arp_packets") or [])
        if not icmp_packets:
            icmp_packets = [p for p in packets if self._transport_protocol(p) == Protocol.ICMP]
        if not arp_packets:
            arp_packets = [p for p in packets if self._transport_protocol(p) == Protocol.ARP]
        icmp_unreachable = sum(1 for p in icmp_packets if p.icmp_type == 3)
        icmp_port_unreachable = sum(1 for p in icmp_packets if p.icmp_type == 3 and p.icmp_code == 3)
        icmp_frag_needed = sum(1 for p in icmp_packets if p.icmp_type == 3 and p.icmp_code == 4)
        icmp_ttl_expired = sum(1 for p in icmp_packets if p.icmp_type == 11)
        arp_total = len(arp_packets)
        arp_requests = sum(1 for p in arp_packets if int(p.arp_opcode or 0) == 1)
        arp_replies = sum(1 for p in arp_packets if int(p.arp_opcode or 0) == 2)

        ip_option_anomaly = sum(
            1
            for p in packets
            if p.ip_options
            and (
                "lsrr" in p.ip_options.lower()
                or "ssrr" in p.ip_options.lower()
                or "source route" in p.ip_options.lower()
            )
        )

        duration = basic.get("duration", 1) or 1
        broadcast_packets = 0
        for p in packets:
            if not p.dst_ip:
                continue
            # IPv4 broadcast/multicast
            if p.dst_ip.endswith(".255") or p.dst_ip == "255.255.255.255":
                broadcast_packets += 1
            elif ":" not in p.dst_ip and p.dst_ip.startswith(tuple(f"{i}." for i in range(224, 240))):
                broadcast_packets += 1
            # IPv6 multicast
            elif p.dst_ip.lower().startswith("ff"):
                broadcast_packets += 1

        send_bytes = (buckets or {}).get("send_bytes")
        recv_bytes = (buckets or {}).get("recv_bytes")
        if send_bytes is None or recv_bytes is None:
            send_bytes = defaultdict(int)
            recv_bytes = defaultdict(int)
            for p in packets:
                if p.src_ip:
                    send_bytes[p.src_ip] += p.length
                if p.dst_ip:
                    recv_bytes[p.dst_ip] += p.length

        asym_ratios = []
        for ip in set(send_bytes.keys()) | set(recv_bytes.keys()):
            s = send_bytes.get(ip, 0)
            r = recv_bytes.get(ip, 0)
            if s > 0 and r > 0:
                asym_ratios.append(max(s / r, r / s))
        max_asym_ratio = max(asym_ratios) if asym_ratios else 1

        ip_to_macs: Dict[str, set] = defaultdict(set)
        for pkt in arp_packets:
            ip = str(pkt.arp_src_ip or pkt.src_ip or "").strip()
            mac = str(pkt.arp_src_mac or "").strip().lower()
            if ip and mac:
                ip_to_macs[ip].add(mac)
        arp_conflicts = {
            ip: sorted(macs)
            for ip, macs in ip_to_macs.items()
            if len(macs) > 1
        }
        arp_conflict_examples = [
            f"{ip} -> {', '.join(macs[:3])}"
            for ip, macs in list(arp_conflicts.items())[:5]
        ]

        return {
            "icmp_unreachable": icmp_unreachable,
            "icmp_port_unreachable": icmp_port_unreachable,
            "icmp_frag_needed": icmp_frag_needed,
            "icmp_ttl_expired": icmp_ttl_expired,
            "arp_total": arp_total,
            "arp_requests": arp_requests,
            "arp_replies": arp_replies,
            "arp_ip_mac_conflicts": len(arp_conflicts),
            "arp_conflict_examples": arp_conflict_examples,
            "ip_option_anomaly": ip_option_anomaly,
            "broadcast_packets": broadcast_packets,
            "broadcast_rate": broadcast_packets / duration,
            "asymmetry_ratio": max_asym_ratio,
        }

    def _extract_udp_metrics(self, buckets: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        udp_packets = list((buckets or {}).get("udp_packets") or [])
        if not udp_packets:
            udp_packets = [p for p in self.packets if self._transport_protocol(p) == Protocol.UDP]
        if not udp_packets:
            return {}

        udp_flows = [f for f in self.flows.values() if f.protocol == Protocol.UDP]
        no_resp_flows = [f for f in udp_flows if any("UDP无响应" in issue for issue in f.issues)]

        return {
            "total_udp": len(udp_packets),
            "flows": len(udp_flows),
            "no_response_flows": len(no_resp_flows),
        }

    def _extract_application_metrics(self, buckets: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        cfg = get_config().get("analysis.thresholds", {}) or {}
        dns_latency_high_ms = float(cfg.get("dns_latency_high_ms", 200))
        http_ttfb_high_ms = float(cfg.get("http_ttfb_high_ms", 800))

        http_total = 0
        http_errors = 0
        http_request_count = 0
        http_response_count = 0
        http_latencies: List[float] = []

        tls_total = 0
        tls_alerts = 0

        dns_total = 0
        dns_errors = 0
        dns_query_count = 0
        dns_response_count = 0
        dns_latencies: List[float] = []
        dns_pending: Dict[Tuple[str, int, str, int, int], List[float]] = defaultdict(list)

        packets = list((buckets or {}).get("packets") or self.packets)
        for p in packets:
            app = self._application_protocol(p)

            if app == Protocol.HTTP:
                http_total += 1
                if p.http_is_request:
                    http_request_count += 1
                if p.http_is_response:
                    http_response_count += 1
                if p.http_status and p.http_status >= 400:
                    http_errors += 1
                if p.http_response_time and p.http_response_time > 0:
                    http_latencies.append(float(p.http_response_time))

            elif app == Protocol.TLS:
                tls_total += 1
                if p.tls_alert_desc:
                    tls_alerts += 1

            elif app == Protocol.DNS:
                dns_total += 1
                if p.dns_rcode is not None and p.dns_rcode != 0:
                    dns_errors += 1

                if p.dns_response_time and p.dns_response_time > 0:
                    dns_latencies.append(float(p.dns_response_time))

                if not p.src_ip or not p.dst_ip or p.src_port is None or p.dst_port is None or p.dns_id is None:
                    continue

                is_response = p.dns_is_response
                if is_response is None:
                    is_response = p.dns_rcode is not None

                key = (p.src_ip, int(p.src_port), p.dst_ip, int(p.dst_port), int(p.dns_id))
                reverse_key = (p.dst_ip, int(p.dst_port), p.src_ip, int(p.src_port), int(p.dns_id))

                if not is_response:
                    dns_query_count += 1
                    dns_pending[key].append(float(p.timestamp))
                else:
                    dns_response_count += 1
                    pending = dns_pending.get(reverse_key)
                    if pending:
                        ts = pending.pop(0)
                        latency = float(p.timestamp) - ts
                        if 0 < latency <= 30:
                            dns_latencies.append(latency)
                        if not pending:
                            dns_pending.pop(reverse_key, None)

        # Merge HTTP per-flow fallback latencies when packet-level timing is missing.
        if not http_latencies:
            for flow in self.flows.values():
                if flow.protocol != Protocol.TCP:
                    continue
                if flow.http_latencies:
                    http_latencies.extend(flow.http_latencies)

        dns_unanswered = sum(len(v) for v in dns_pending.values())
        dns_slow_count = sum(1 for x in dns_latencies if x * 1000 >= dns_latency_high_ms)
        http_slow_count = sum(1 for x in http_latencies if x * 1000 >= http_ttfb_high_ms)

        return {
            "http_total": http_total,
            "http_requests": http_request_count,
            "http_responses": http_response_count,
            "http_error_responses": http_errors,
            "http_latency_avg_ms": (statistics.mean(http_latencies) * 1000) if http_latencies else 0,
            "http_latency_p95_ms": (self._percentile(http_latencies, 0.95) * 1000) if http_latencies else 0,
            "http_slow_count": http_slow_count,
            "http_latency_samples": len(http_latencies),
            "tls_total": tls_total,
            "tls_alerts": tls_alerts,
            "dns_total": dns_total,
            "dns_queries": dns_query_count,
            "dns_responses": dns_response_count,
            "dns_error_rcode": dns_errors,
            "dns_unanswered": dns_unanswered,
            "dns_latency_avg_ms": (statistics.mean(dns_latencies) * 1000) if dns_latencies else 0,
            "dns_latency_p95_ms": (self._percentile(dns_latencies, 0.95) * 1000) if dns_latencies else 0,
            "dns_slow_count": dns_slow_count,
            "dns_latency_samples": len(dns_latencies),
        }

    def _extract_traffic_timeline(
        self,
        basic: Dict[str, Any],
        buckets: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build global traffic timeline series for visualization."""
        packets = list((buckets or {}).get("packets") or self.packets)
        if not packets:
            return {}

        cfg = get_config()
        dyn_cfg = cfg.get("analysis.dynamic_threshold", {}) or {}
        window_seconds = float(dyn_cfg.get("window_seconds", 10) or 10)
        if window_seconds <= 0:
            window_seconds = 10.0

        duration = float(basic.get("duration", 0) or 0)
        if duration > 0:
            max_points = 120
            if duration / window_seconds > max_points:
                window_seconds = max(duration / max_points, 1.0)

        start_time = float(basic.get("start_time", 0) or 0)
        windows: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {
                "total_packets": 0,
                "total_bytes": 0,
                "tcp_packets": 0,
                "udp_packets": 0,
                "icmp_packets": 0,
                "arp_packets": 0,
                "dns_packets": 0,
                "http_packets": 0,
                "retransmissions": 0,
                "rst": 0,
                "rtts": [],
            }
        )
        seq_seen: Dict[Tuple[int, str, int, str, int], set] = defaultdict(set)

        for packet in packets:
            idx = int((float(packet.timestamp) - start_time) // window_seconds) if window_seconds > 0 else 0
            if idx < 0:
                idx = 0
            win = windows[idx]
            win["total_packets"] += 1
            win["total_bytes"] += int(packet.length or 0)

            transport = self._transport_protocol(packet)
            app = self._application_protocol(packet)
            if transport == Protocol.TCP:
                win["tcp_packets"] += 1
                if self._is_tcp_flag_set(packet.tcp_flags, "R"):
                    win["rst"] += 1
                if packet.tcp_rtt:
                    win["rtts"].append(float(packet.tcp_rtt))

                is_retrans = False
                if packet.src_ip and packet.dst_ip:
                    seq_key = (
                        idx,
                        packet.src_ip,
                        int(packet.src_port or 0),
                        packet.dst_ip,
                        int(packet.dst_port or 0),
                    )
                    is_retrans = self._is_retransmission_event(packet, seq_seen[seq_key])
                if is_retrans:
                    win["retransmissions"] += 1
            elif transport == Protocol.UDP:
                win["udp_packets"] += 1
            elif transport == Protocol.ICMP:
                win["icmp_packets"] += 1
            elif transport == Protocol.ARP:
                win["arp_packets"] += 1

            if app == Protocol.DNS:
                win["dns_packets"] += 1
            elif app == Protocol.HTTP:
                win["http_packets"] += 1

        if not windows:
            return {}

        points: List[Dict[str, Any]] = []
        for idx in sorted(windows.keys()):
            win = windows[idx]
            tcp_packets = int(win["tcp_packets"] or 0)
            points.append(
                {
                    "index": idx,
                    "time_s": round(idx * window_seconds, 3),
                    "total_packets": int(win["total_packets"] or 0),
                    "total_bytes": int(win["total_bytes"] or 0),
                    "packets_per_sec": float(win["total_packets"] or 0) / window_seconds,
                    "throughput_mbps": (float(win["total_bytes"] or 0) * 8.0 / window_seconds) / 1_000_000.0,
                    "tcp_packets": tcp_packets,
                    "udp_packets": int(win["udp_packets"] or 0),
                    "icmp_packets": int(win["icmp_packets"] or 0),
                    "arp_packets": int(win["arp_packets"] or 0),
                    "dns_packets": int(win["dns_packets"] or 0),
                    "http_packets": int(win["http_packets"] or 0),
                    "retransmissions": int(win["retransmissions"] or 0),
                    "rst": int(win["rst"] or 0),
                    "retrans_rate": float(win["retransmissions"] or 0) / max(tcp_packets, 1),
                    "rst_rate": float(win["rst"] or 0) / max(tcp_packets, 1),
                    "avg_rtt_ms": (statistics.mean(win["rtts"]) * 1000.0) if win["rtts"] else 0.0,
                }
            )

        return {
            "window_seconds": window_seconds,
            "point_count": len(points),
            "series": points,
        }

    def _extract_ip_topology(self, buckets: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Aggregate IP communication topology for graph rendering."""
        packets = list((buckets or {}).get("packets") or self.packets)
        if not packets:
            return {}

        cfg = get_config()
        report_cfg = cfg.get("report", {}) or {}
        max_nodes = int(report_cfg.get("top_n", 10) or 10) * 2
        if max_nodes < 8:
            max_nodes = 8
        max_edges = max(max_nodes * 3, 24)

        nodes: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "ip": "",
                "send_packets": 0,
                "recv_packets": 0,
                "send_bytes": 0,
                "recv_bytes": 0,
                "total_packets": 0,
                "total_bytes": 0,
                "incident_score": 0.0,
            }
        )
        edges: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(
            lambda: {
                "src_ip": "",
                "dst_ip": "",
                "packets": 0,
                "bytes": 0,
                "protocol_breakdown": defaultdict(int),
                "retrans_count": 0,
                "rst_count": 0,
                "issue_score": 0.0,
                "first_ts": None,
                "last_ts": None,
            }
        )

        for packet in packets:
            if not packet.src_ip or not packet.dst_ip:
                continue

            src = packet.src_ip
            dst = packet.dst_ip

            src_node = nodes[src]
            src_node["ip"] = src
            src_node["send_packets"] += 1
            src_node["send_bytes"] += int(packet.length or 0)
            src_node["total_packets"] += 1
            src_node["total_bytes"] += int(packet.length or 0)

            dst_node = nodes[dst]
            dst_node["ip"] = dst
            dst_node["recv_packets"] += 1
            dst_node["recv_bytes"] += int(packet.length or 0)
            dst_node["total_packets"] += 1
            dst_node["total_bytes"] += int(packet.length or 0)

            edge_key = (src, dst)
            edge = edges[edge_key]
            edge["src_ip"] = src
            edge["dst_ip"] = dst
            edge["packets"] += 1
            edge["bytes"] += int(packet.length or 0)
            edge["protocol_breakdown"][self._transport_protocol(packet).value] += 1
            edge["first_ts"] = (
                float(packet.timestamp)
                if edge["first_ts"] is None
                else min(float(edge["first_ts"]), float(packet.timestamp))
            )
            edge["last_ts"] = (
                float(packet.timestamp)
                if edge["last_ts"] is None
                else max(float(edge["last_ts"]), float(packet.timestamp))
            )

            if self._transport_protocol(packet) == Protocol.TCP:
                if bool(packet.is_retransmission):
                    edge["retrans_count"] += 1
                if self._is_tcp_flag_set(packet.tcp_flags, "R"):
                    edge["rst_count"] += 1

        if not nodes or not edges:
            return {}

        for edge in edges.values():
            retrans = int(edge.get("retrans_count", 0) or 0)
            rst = int(edge.get("rst_count", 0) or 0)
            edge["issue_score"] = float(rst * 6 + retrans * 3)
            if edge.get("protocol_breakdown"):
                edge["dominant_protocol"] = max(
                    edge["protocol_breakdown"].items(),
                    key=lambda item: item[1],
                )[0]
            else:
                edge["dominant_protocol"] = "OTHER"

        for node in nodes.values():
            ip = node.get("ip", "")
            outgoing_issue = sum(
                float(edge.get("issue_score", 0.0) or 0.0)
                for edge in edges.values()
                if edge.get("src_ip") == ip
            )
            incoming_issue = sum(
                float(edge.get("issue_score", 0.0) or 0.0)
                for edge in edges.values()
                if edge.get("dst_ip") == ip
            )
            node["incident_score"] = outgoing_issue + incoming_issue

        sorted_nodes = sorted(
            nodes.values(),
            key=lambda node: (
                int(node.get("total_packets", 0) or 0),
                int(node.get("total_bytes", 0) or 0),
            ),
            reverse=True,
        )
        top_node_ips = {str(node.get("ip")) for node in sorted_nodes[:max_nodes]}

        sorted_edges_all = sorted(
            edges.values(),
            key=lambda edge: (
                int(edge.get("packets", 0) or 0),
                float(edge.get("issue_score", 0.0) or 0.0),
                int(edge.get("bytes", 0) or 0),
            ),
            reverse=True,
        )
        top_edges: List[Dict[str, Any]] = []
        for edge in sorted_edges_all:
            if edge.get("src_ip") in top_node_ips and edge.get("dst_ip") in top_node_ips:
                top_edges.append(edge)
            if len(top_edges) >= max_edges:
                break
        if not top_edges:
            top_edges = sorted_edges_all[:max_edges]

        selected_ips = {
            str(edge.get("src_ip"))
            for edge in top_edges
            if edge.get("src_ip")
        } | {
            str(edge.get("dst_ip"))
            for edge in top_edges
            if edge.get("dst_ip")
        }

        top_nodes = [node for node in sorted_nodes if node.get("ip") in selected_ips]
        if not top_nodes:
            top_nodes = sorted_nodes[:max_nodes]

        normalized_edges: List[Dict[str, Any]] = []
        for edge in top_edges:
            proto_breakdown = dict(edge.get("protocol_breakdown", {}))
            normalized_edges.append(
                {
                    "src_ip": edge.get("src_ip", ""),
                    "dst_ip": edge.get("dst_ip", ""),
                    "packets": int(edge.get("packets", 0) or 0),
                    "bytes": int(edge.get("bytes", 0) or 0),
                    "dominant_protocol": edge.get("dominant_protocol", "OTHER"),
                    "protocol_breakdown": proto_breakdown,
                    "retrans_count": int(edge.get("retrans_count", 0) or 0),
                    "rst_count": int(edge.get("rst_count", 0) or 0),
                    "issue_score": float(edge.get("issue_score", 0.0) or 0.0),
                    "duration_s": (
                        float(edge.get("last_ts", 0.0) or 0.0) - float(edge.get("first_ts", 0.0) or 0.0)
                        if edge.get("first_ts") is not None and edge.get("last_ts") is not None
                        else 0.0
                    ),
                }
            )

        return {
            "node_count": len(top_nodes),
            "edge_count": len(normalized_edges),
            "nodes": top_nodes,
            "edges": normalized_edges,
        }

    def _extract_tcp_streams(self) -> Dict[str, Any]:
        """Reconstruct TCP streams and produce Follow Stream previews."""
        tcp_packets = [
            packet
            for packet in self.packets
            if self._transport_protocol(packet) == Protocol.TCP and packet.src_ip and packet.dst_ip
        ]
        if not tcp_packets:
            return {}

        cfg = get_config()
        report_cfg = cfg.get("report", {}) or {}
        top_n = int(report_cfg.get("top_n", 10) or 10)
        max_streams = max(3, top_n)
        max_payload_bytes = int((cfg.get("analysis", {}) or {}).get("max_follow_stream_bytes", 16384) or 16384)
        if max_payload_bytes <= 0:
            max_payload_bytes = 16384

        stream_map: Dict[str, Dict[str, Any]] = {}
        sorted_packets = sorted(
            tcp_packets,
            key=lambda pkt: (float(pkt.timestamp), int(pkt.number)),
        )

        for packet in sorted_packets:
            stream_key = self._stream_group_key(packet)
            stream = stream_map.get(stream_key)
            if stream is None:
                stream_id: Any
                if packet.tcp_stream_id is not None:
                    stream_id = int(packet.tcp_stream_id)
                else:
                    stream_id = stream_key.replace("flow:", "")
                stream = {
                    "stream_key": stream_key,
                    "stream_id": stream_id,
                    "packet_count": 0,
                    "total_bytes": 0,
                    "payload_bytes": 0,
                    "retrans_count": 0,
                    "rst_count": 0,
                    "syn_count": 0,
                    "syn_ack_count": 0,
                    "ack_count": 0,
                    "client_endpoint": None,
                    "server_endpoint": None,
                    "first_ts": None,
                    "last_ts": None,
                    "first_packet_no": 0,
                    "last_packet_no": 0,
                    "segments_c2s": [],
                    "segments_s2c": [],
                    "client_to_server_payload_bytes": 0,
                    "server_to_client_payload_bytes": 0,
                }
                stream_map[stream_key] = stream

            stream["packet_count"] += 1
            stream["total_bytes"] += int(packet.length or 0)
            stream["first_ts"] = (
                float(packet.timestamp)
                if stream["first_ts"] is None
                else min(float(stream["first_ts"]), float(packet.timestamp))
            )
            stream["last_ts"] = (
                float(packet.timestamp)
                if stream["last_ts"] is None
                else max(float(stream["last_ts"]), float(packet.timestamp))
            )
            if stream["first_packet_no"] == 0:
                stream["first_packet_no"] = int(packet.number or 0)
            stream["last_packet_no"] = max(int(stream["last_packet_no"] or 0), int(packet.number or 0))

            has_syn = self._is_tcp_flag_set(packet.tcp_flags, "S")
            has_ack = self._is_tcp_flag_set(packet.tcp_flags, "A")
            if has_syn and not has_ack:
                stream["syn_count"] += 1
                if stream["client_endpoint"] is None:
                    stream["client_endpoint"] = (packet.src_ip, int(packet.src_port or 0))
                    stream["server_endpoint"] = (packet.dst_ip, int(packet.dst_port or 0))
            elif has_syn and has_ack:
                stream["syn_ack_count"] += 1
            if has_ack:
                stream["ack_count"] += 1

            if self._is_tcp_flag_set(packet.tcp_flags, "R"):
                stream["rst_count"] += 1
            if bool(packet.is_retransmission):
                stream["retrans_count"] += 1

            if stream["client_endpoint"] is None:
                stream["client_endpoint"] = (packet.src_ip, int(packet.src_port or 0))
                stream["server_endpoint"] = (packet.dst_ip, int(packet.dst_port or 0))

            payload = self._payload_bytes(packet)
            if not payload:
                continue

            stream["payload_bytes"] += len(payload)
            client_ep = stream["client_endpoint"]
            server_ep = stream["server_endpoint"]
            direction = "c2s"
            if client_ep and server_ep:
                if (
                    packet.src_ip == client_ep[0]
                    and int(packet.src_port or 0) == int(client_ep[1] or 0)
                    and packet.dst_ip == server_ep[0]
                    and int(packet.dst_port or 0) == int(server_ep[1] or 0)
                ):
                    direction = "c2s"
                elif (
                    packet.src_ip == server_ep[0]
                    and int(packet.src_port or 0) == int(server_ep[1] or 0)
                    and packet.dst_ip == client_ep[0]
                    and int(packet.dst_port or 0) == int(client_ep[1] or 0)
                ):
                    direction = "s2c"
                elif int(packet.src_port or 0) == int(client_ep[1] or 0):
                    direction = "c2s"
                else:
                    direction = "s2c"

            segment = {
                "seq": int(packet.tcp_seq or 0),
                "timestamp": float(packet.timestamp),
                "packet_no": int(packet.number or 0),
                "payload": payload,
            }
            if direction == "c2s":
                stream["segments_c2s"].append(segment)
                stream["client_to_server_payload_bytes"] += len(payload)
            else:
                stream["segments_s2c"].append(segment)
                stream["server_to_client_payload_bytes"] += len(payload)

        stream_rows: List[Dict[str, Any]] = []
        streams_with_payload = 0
        for stream in stream_map.values():
            c2s_result = self._reassemble_segments(stream["segments_c2s"], max_payload_bytes)
            s2c_result = self._reassemble_segments(stream["segments_s2c"], max_payload_bytes)
            c2s_data = c2s_result["data"]
            s2c_data = s2c_result["data"]
            if c2s_data or s2c_data:
                streams_with_payload += 1

            client_ep = stream.get("client_endpoint") or ("unknown", 0)
            server_ep = stream.get("server_endpoint") or ("unknown", 0)
            client_text = self._safe_ascii_preview(c2s_data, char_limit=1200)
            server_text = self._safe_ascii_preview(s2c_data, char_limit=1200)
            client_hex = self._hex_preview(c2s_data, byte_limit=256)
            server_hex = self._hex_preview(s2c_data, byte_limit=256)

            issue_score = (
                float(stream.get("rst_count", 0) or 0) * 8
                + float(stream.get("retrans_count", 0) or 0) * 4
                + min(float(stream.get("payload_bytes", 0) or 0) / 2048.0, 20)
            )
            if int(stream.get("syn_count", 0) or 0) > 0 and int(stream.get("syn_ack_count", 0) or 0) == 0:
                issue_score += 12
            if int(stream.get("syn_ack_count", 0) or 0) > 0 and int(stream.get("ack_count", 0) or 0) == 0:
                issue_score += 10

            stream_rows.append(
                {
                    "stream_id": stream.get("stream_id"),
                    "stream_key": stream.get("stream_key"),
                    "client_endpoint": f"{client_ep[0]}:{int(client_ep[1] or 0)}",
                    "server_endpoint": f"{server_ep[0]}:{int(server_ep[1] or 0)}",
                    "packet_count": int(stream.get("packet_count", 0) or 0),
                    "total_bytes": int(stream.get("total_bytes", 0) or 0),
                    "payload_bytes": int(stream.get("payload_bytes", 0) or 0),
                    "client_to_server_payload_bytes": int(stream.get("client_to_server_payload_bytes", 0) or 0),
                    "server_to_client_payload_bytes": int(stream.get("server_to_client_payload_bytes", 0) or 0),
                    "retrans_count": int(stream.get("retrans_count", 0) or 0),
                    "rst_count": int(stream.get("rst_count", 0) or 0),
                    "duration_s": (
                        float(stream.get("last_ts", 0.0) or 0.0) - float(stream.get("first_ts", 0.0) or 0.0)
                        if stream.get("first_ts") is not None and stream.get("last_ts") is not None
                        else 0.0
                    ),
                    "first_packet_no": int(stream.get("first_packet_no", 0) or 0),
                    "last_packet_no": int(stream.get("last_packet_no", 0) or 0),
                    "issue_score": issue_score,
                    "has_payload": bool(c2s_data or s2c_data),
                    "client_to_server_text": client_text,
                    "server_to_client_text": server_text,
                    "client_to_server_hex": client_hex,
                    "server_to_client_hex": server_hex,
                    "client_used_segments": int(c2s_result.get("used_segments", 0) or 0),
                    "server_used_segments": int(s2c_result.get("used_segments", 0) or 0),
                    "client_dropped_segments": int(c2s_result.get("dropped_segments", 0) or 0),
                    "server_dropped_segments": int(s2c_result.get("dropped_segments", 0) or 0),
                }
            )

        ranked = sorted(
            stream_rows,
            key=lambda row: (
                bool(row.get("has_payload")),
                float(row.get("issue_score", 0.0) or 0.0),
                int(row.get("payload_bytes", 0) or 0),
                int(row.get("packet_count", 0) or 0),
            ),
            reverse=True,
        )

        return {
            "total_streams": len(stream_rows),
            "streams_with_payload": streams_with_payload,
            "top_streams": ranked[:max_streams],
        }
