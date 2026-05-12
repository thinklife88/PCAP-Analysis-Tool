#!/usr/bin/env python3
"""PCAP analyzer entrypoint."""

import os
import ipaddress
import importlib.util
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import typer

from core.metrics import MetricsExtractor
from core.parser import PcapParser
from diagnosis.advanced_rules import get_advanced_rules
from diagnosis.engine import DetectionEngine
from diagnosis.inference import InferenceEngine
from diagnosis.rules import get_all_rules
from report.generator import ReportGenerator
from ui.display import create_progress, print_error, print_header, print_info, print_success, print_warning
from ui.menu import Menu
from utils.ai_config import AIConfig
from utils.config import get_config
from utils.logger import setup_logger
from utils.tshark_finder import TSharkFinder
from utils.validator import FileValidator

app = typer.Typer(help="PCAP 抓包分析工具")
logger = setup_logger()


def check_tshark() -> bool:
    """Check tshark availability."""
    tshark_path = TSharkFinder.find_tshark()
    if not tshark_path:
        print_error("未找到 tshark")
        if typer.confirm("是否启动 tshark 配置向导？", default=True):
            tshark_path = TSharkFinder.interactive_setup()
            if tshark_path:
                os.environ["TSHARK_PATH"] = tshark_path
                return True
        return False

    os.environ["TSHARK_PATH"] = tshark_path
    logger.info(f"Using tshark: {tshark_path}")
    return True


class Analyzer:
    def __init__(self):
        self.config = get_config()
        self.menu = Menu()
        self.plugins = self._load_plugins()

    def _load_plugins(self) -> List[object]:
        plugins = []
        if not self.config.get("plugins.enabled", True):
            return plugins
        if not self.config.get("plugins.auto_load", True):
            return plugins

        plugin_dir = Path(self.config.get("plugins.directory", "plugins"))
        if not plugin_dir.exists():
            return plugins

        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                plugins.append(module)
            except Exception as exc:
                logger.warning(f"Plugin load failed: {py_file}: {exc}")
        return plugins

    def _register_plugin_rules(self, detection_engine: DetectionEngine):
        for plugin in self.plugins:
            try:
                if hasattr(plugin, "register"):
                    plugin.register(detection_engine)
            except Exception as exc:
                logger.warning(f"Plugin register failed: {plugin}: {exc}")

    def run_interactive(self):
        print_header("PCAP 分析工具")
        while True:
            choice = self.menu.show_main_menu()

            if choice == "0":
                AIConfig.interactive_setup()
            elif choice == "1":
                file_path = self.menu.get_file_path()
                if file_path:
                    self._analyze_file(file_path)
            elif choice == "2":
                file_path = self.menu.select_from_history()
                if file_path:
                    self._analyze_file(file_path)
            elif choice == "3":
                self._scan_directory()
            elif choice == "4":
                self._show_history()
            elif choice == "5":
                self.menu.clear_history()
            elif choice == "6":
                self.menu.query_error()
            elif choice == "7":
                self.menu.reset_program()
            elif choice == "8":
                print_success("已退出")
                break

    def _scan_directory(self):
        dir_path = self.menu.get_directory_path()
        if not dir_path:
            return

        files = self._find_capture_files(dir_path)
        if not files:
            print_info("目录中未发现 .pcap/.pcapng 文件")
            return

        selected = self.menu.select_file_from_directory(files)
        if selected is None:
            return

        if selected == "__ALL__":
            print_info(f"批量分析 {len(files)} 个抓包文件")
            analysis_filter = self.menu.select_analysis_scope()
            mode = self.menu.select_analysis_mode()
            execution_options = self._resolve_batch_preferences(mode)
            for idx, file_path in enumerate(files, 1):
                try:
                    print_info(f"[{idx}/{len(files)}] Processing: {file_path.name}")
                    self._analyze_file(
                        str(file_path),
                        mode=mode,
                        analysis_filter=analysis_filter,
                        execution_options=execution_options,
                    )
                except Exception as exc:
                    logger.error(f"Batch analyze failed for {file_path}: {exc}")
                    print_error(f"分析失败: {file_path}")
        else:
            self._analyze_file(selected)

    @staticmethod
    def _find_capture_files(dir_path: str) -> List[Path]:
        root = Path(dir_path)
        files = list(root.rglob("*.pcap")) + list(root.rglob("*.pcapng"))
        files.sort()
        return files

    def _resolve_batch_preferences(self, mode: str) -> Dict[str, Any]:
        options: Dict[str, Any] = {}
        if AIConfig.is_enabled():
            options["use_ai"] = typer.confirm(
                "Batch run: enable AI analysis for all files?",
                default=False,
            )
        else:
            options["use_ai"] = False

        if mode == "quick":
            options["generate_report"] = True
            options["report_formats"] = ["html"]
            return options

        options["generate_report"] = typer.confirm(
            "Batch run: generate reports for all files?",
            default=True,
        )
        if options["generate_report"]:
            options["report_formats"] = self.menu.select_report_formats()
        else:
            options["report_formats"] = []
        return options

    @staticmethod
    def _normalize_ip(ip_value: Optional[str]) -> str:
        text = str(ip_value or "").strip()
        if not text:
            return ""
        try:
            return ipaddress.ip_address(text).compressed
        except ValueError:
            return text.lower()

    @staticmethod
    def _normalize_scope_ports(port_value: Any) -> List[int]:
        if port_value is None:
            return []
        if isinstance(port_value, int):
            values = [port_value]
        elif isinstance(port_value, str):
            values = []
            for part in port_value.split(","):
                part = part.strip()
                if not part:
                    continue
                try:
                    values.append(int(part))
                except ValueError:
                    continue
        else:
            values = []
            for item in port_value if isinstance(port_value, list) else [port_value]:
                try:
                    values.append(int(item))
                except Exception:
                    continue
        normalized: List[int] = []
        for p in values:
            if 1 <= int(p) <= 65535:
                normalized.append(int(p))
        return sorted(set(normalized))

    @staticmethod
    def _normalize_scope_protocol(protocol_value: Optional[str]) -> Optional[str]:
        text = str(protocol_value or "").strip().lower()
        if not text:
            return None
        alias = {
            "icmpv6": "icmp",
            "https": "tls",
        }
        text = alias.get(text, text)
        supported = {"tcp", "udp", "icmp", "arp", "dns", "http", "tls"}
        if text not in supported:
            return None
        return text

    @staticmethod
    def _normalize_scope_filter(analysis_filter: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        src = analysis_filter or {}
        ip_value = Analyzer._normalize_ip(src.get("ip"))
        ports = Analyzer._normalize_scope_ports(src.get("ports") or src.get("port"))
        protocol = Analyzer._normalize_scope_protocol(src.get("protocol"))
        mode = str(src.get("mode", "all") or "all").strip().lower()
        display_filter = str(src.get("display_filter", "") or "").strip() or None

        time_start = src.get("time_start")
        time_end = src.get("time_end")
        try:
            time_start = float(time_start) if time_start is not None else None
        except Exception:
            time_start = None
        try:
            time_end = float(time_end) if time_end is not None else None
        except Exception:
            time_end = None
        if time_start is not None and time_start < 0:
            time_start = 0.0
        if time_end is not None and time_end < 0:
            time_end = None
        if time_start is not None and time_end is not None and time_end < time_start:
            time_start, time_end = time_end, time_start

        has_scope = bool(ip_value or ports or protocol or display_filter or time_start is not None or time_end is not None)
        if mode == "all" and has_scope:
            mode = "custom"
        if mode == "ip" and not ip_value:
            mode = "all"
        if mode not in {"all", "ip", "custom"}:
            mode = "custom" if has_scope else "all"

        return {
            "mode": mode,
            "ip": ip_value or None,
            "ports": ports,
            "protocol": protocol,
            "time_start": time_start,
            "time_end": time_end,
            "display_filter": display_filter,
        }

    @staticmethod
    def _build_parser_display_filter(analysis_filter: Optional[Dict[str, Any]]) -> Optional[str]:
        filt = analysis_filter or {}
        custom = str(filt.get("display_filter", "") or "").strip()
        if custom:
            return custom
        # Keep parser-side filtering conservative for stability;
        # IP/port/protocol/time scopes are applied in local packet filtering.
        return None

    @staticmethod
    def _format_analysis_scope(analysis_filter: Optional[Dict[str, Any]]) -> str:
        if not analysis_filter:
            return "all traffic"
        filt = Analyzer._normalize_scope_filter(analysis_filter)
        if filt.get("mode") == "all":
            return "all traffic"

        parts: List[str] = []
        scope_ip = filt.get("ip")
        if scope_ip:
            parts.append(f"ip={scope_ip}")
        ports = Analyzer._normalize_scope_ports(filt.get("ports"))
        if ports:
            port_text = ",".join([str(p) for p in ports[:6]])
            if len(ports) > 6:
                port_text += ",..."
            parts.append(f"port={port_text}")
        protocol = filt.get("protocol")
        if protocol:
            parts.append(f"protocol={protocol.upper()}")
        time_start = filt.get("time_start")
        time_end = filt.get("time_end")
        if time_start is not None or time_end is not None:
            left = f"{float(time_start):.2f}s" if time_start is not None else "start"
            right = f"{float(time_end):.2f}s" if time_end is not None else "end"
            parts.append(f"time=[{left},{right}]")
        display_filter = str(filt.get("display_filter", "") or "").strip()
        if display_filter:
            if len(display_filter) > 48:
                display_filter = display_filter[:47] + "..."
            parts.append(f"filter={display_filter}")
        return "scope: " + ", ".join(parts) if parts else "all traffic"

    @staticmethod
    def _packet_in_scope(
        packet,
        analysis_filter: Optional[Dict[str, Any]],
        base_time: Optional[float] = None,
    ) -> bool:
        filt = Analyzer._normalize_scope_filter(analysis_filter)
        if filt.get("mode") == "all":
            return True

        target_ip = Analyzer._normalize_ip(filt.get("ip"))
        if target_ip:
            src_ip = Analyzer._normalize_ip(getattr(packet, "src_ip", None))
            dst_ip = Analyzer._normalize_ip(getattr(packet, "dst_ip", None))
            if src_ip != target_ip and dst_ip != target_ip:
                return False

        ports = Analyzer._normalize_scope_ports(filt.get("ports"))
        if ports:
            src_port = getattr(packet, "src_port", None)
            dst_port = getattr(packet, "dst_port", None)
            if src_port not in ports and dst_port not in ports:
                return False

        protocol = Analyzer._normalize_scope_protocol(filt.get("protocol"))
        if protocol:
            transport = str(getattr(getattr(packet, "transport_protocol", None), "value", "") or "").lower()
            app_proto = str(getattr(getattr(packet, "application_protocol", None), "value", "") or "").lower()
            if protocol in {"dns", "http", "tls"}:
                if app_proto != protocol:
                    return False
            else:
                if transport != protocol:
                    return False

        time_start = filt.get("time_start")
        time_end = filt.get("time_end")
        if time_start is not None or time_end is not None:
            packet_ts = float(getattr(packet, "timestamp", 0.0) or 0.0)
            if base_time is not None:
                packet_ts -= float(base_time)
            if time_start is not None and packet_ts < float(time_start):
                return False
            if time_end is not None and packet_ts > float(time_end):
                return False

        return True

    def _resolve_quick_ip_packet_limit(self, file_path: str, interactive_mode: bool = True) -> Optional[int]:
        guard_enabled = bool(self.config.get("analysis.quick_ip_guard.enabled", True))
        if not guard_enabled:
            return None

        warn_value = self.config.get("analysis.quick_ip_guard.file_size_mb_warn", 500)
        max_value = self.config.get("analysis.quick_ip_guard.max_packets", 0)
        adaptive_per_mb_value = self.config.get("analysis.quick_ip_guard.adaptive_packets_per_mb", 1200)
        adaptive_min_value = self.config.get("analysis.quick_ip_guard.adaptive_min_packets", 80000)
        adaptive_max_value = self.config.get("analysis.quick_ip_guard.adaptive_max_packets", 300000)
        warn_mb = float(500 if warn_value is None else warn_value)
        max_packets = int(0 if max_value is None else max_value)
        adaptive_per_mb = int(1200 if adaptive_per_mb_value is None else adaptive_per_mb_value)
        adaptive_min = int(80000 if adaptive_min_value is None else adaptive_min_value)
        adaptive_max = int(300000 if adaptive_max_value is None else adaptive_max_value)
        if adaptive_per_mb <= 0:
            adaptive_per_mb = 1200
        if adaptive_min <= 0:
            adaptive_min = 80000
        if adaptive_max > 0 and adaptive_max < adaptive_min:
            adaptive_max = adaptive_min

        try:
            file_size_mb = Path(file_path).stat().st_size / 1024 / 1024
        except OSError:
            return None

        adaptive_packets = int(max(file_size_mb * adaptive_per_mb, adaptive_min))
        if adaptive_max > 0:
            adaptive_packets = min(adaptive_packets, adaptive_max)
        if max_packets <= 0:
            max_packets = adaptive_packets
        else:
            max_packets = min(max_packets, adaptive_packets) if adaptive_packets > 0 else max_packets

        if file_size_mb >= warn_mb:
            print_warning(f"Quick scoped scan on large file ({file_size_mb:.1f} MB) may take longer.")
            if interactive_mode and not typer.confirm("Continue with quick scoped scan?", default=True):
                return 0

        if max_packets > 0:
            print_info(
                "Quick scoped adaptive sampling: "
                f"file={file_size_mb:.1f} MB, cap={max_packets:,} packets."
            )
            return max_packets
        return adaptive_packets if adaptive_packets > 0 else None

    def _resolve_memory_packet_limit(self, max_packets: Optional[int]) -> Optional[int]:
        """Apply a soft packet limit from memory budget to reduce OOM risk."""
        max_memory_mb = int(self.config.get("analysis.max_memory_mb", 0) or 0)
        if max_memory_mb <= 0:
            return max_packets

        bytes_per_packet_est = int(self.config.get("analysis.memory_packet_bytes_estimate", 1200) or 1200)
        if bytes_per_packet_est < 256:
            bytes_per_packet_est = 256

        memory_budget_bytes = max_memory_mb * 1024 * 1024
        soft_limit = int(memory_budget_bytes / bytes_per_packet_est)
        if soft_limit <= 0:
            return max_packets

        if max_packets is None or max_packets <= 0:
            return soft_limit
        return min(int(max_packets), soft_limit)

    def _analyze_file(
        self,
        file_path: str,
        mode: Optional[str] = None,
        analysis_filter: Optional[Dict[str, Any]] = None,
        execution_options: Optional[Dict[str, Any]] = None,
    ):
        try:
            print_header(f"Analyzing: {Path(file_path).name}")
            if analysis_filter is None:
                analysis_filter = self.menu.select_analysis_scope()
            analysis_filter = self._normalize_scope_filter(analysis_filter)
            scope_text = self._format_analysis_scope(analysis_filter)
            print_info(f"Scope: {scope_text}")

            if mode is None:
                mode = self.menu.select_analysis_mode()

            if mode == "quick" and analysis_filter.get("mode") == "all":
                max_packets = 50000
                print_info("Quick mode: analyze first 50,000 packets for full-traffic scan.")
            elif mode == "quick":
                quick_limit = self._resolve_quick_ip_packet_limit(
                    file_path,
                    interactive_mode=execution_options is None,
                )
                if quick_limit == 0:
                    print_info("Canceled by user.")
                    return
                max_packets = quick_limit
                if max_packets:
                    print_info(f"Quick scoped guard enabled, limit={max_packets:,} packets.")
                else:
                    print_info("Quick scoped mode: fallback to full-file scan.")
            else:
                max_packets = None

            memory_limited_packets = self._resolve_memory_packet_limit(max_packets)
            if memory_limited_packets is not None and (
                max_packets is None or int(memory_limited_packets) < int(max_packets)
            ):
                print_warning(
                    "Memory safety guard enabled: "
                    f"parsing at most {int(memory_limited_packets):,} packets "
                    f"(analysis.max_memory_mb={int(self.config.get('analysis.max_memory_mb', 0) or 0)})."
                )
            max_packets = memory_limited_packets

            parser_display_filter = self._build_parser_display_filter(analysis_filter)
            if parser_display_filter:
                print_info(f"Parser display filter enabled: {parser_display_filter}")
            parser = PcapParser(file_path, display_filter=parser_display_filter)
            metrics = MetricsExtractor()
            seen_packets = 0
            matched_packets = 0
            timeout_hit = False
            timeout_seconds = float(self.config.get("analysis.timeout_seconds", 0) or 0)
            parse_started_at = time.monotonic()
            scope_base_time: Optional[float] = None

            def _run_parse(current_parser: PcapParser, reset_counters: bool = False):
                nonlocal seen_packets, matched_packets, timeout_hit, parse_started_at, scope_base_time
                if reset_counters:
                    seen_packets = 0
                    matched_packets = 0
                    timeout_hit = False
                    parse_started_at = time.monotonic()
                    scope_base_time = None
                with create_progress() as progress:
                    task = progress.add_task("Parsing packets... read 0, matched 0", total=None)
                    progress_batch = 200
                    pending_advance = 0
                    for packet in current_parser.parse(max_packets=max_packets):
                        seen_packets += 1
                        pending_advance += 1
                        if scope_base_time is None:
                            scope_base_time = float(getattr(packet, "timestamp", 0.0) or 0.0)
                        if self._packet_in_scope(packet, analysis_filter, base_time=scope_base_time):
                            metrics.add_packet(packet)
                            matched_packets += 1
                        if seen_packets % progress_batch == 0:
                            progress.update(
                                task,
                                advance=pending_advance,
                                description=f"Parsing packets... read {seen_packets:,}, matched {matched_packets:,}",
                            )
                            pending_advance = 0
                            if timeout_seconds > 0 and (time.monotonic() - parse_started_at) >= timeout_seconds:
                                timeout_hit = True
                                print_warning(
                                    f"Analysis timeout reached ({timeout_seconds:.0f}s); "
                                    "stop parsing and continue with partial result."
                                )
                                break
                    if pending_advance > 0:
                        progress.update(
                            task,
                            advance=pending_advance,
                            description=f"Parsing packets... read {seen_packets:,}, matched {matched_packets:,}",
                        )

            try:
                _run_parse(parser, reset_counters=False)
            except Exception as parse_exc:
                if parser_display_filter:
                    print_warning(
                        "Parser display filter failed, fallback to full parse + local scope filtering: "
                        f"{parse_exc}"
                    )
                    parser = PcapParser(file_path)
                    metrics = MetricsExtractor()
                    _run_parse(parser, reset_counters=True)
                else:
                    raise

            limit_hit = bool(max_packets and seen_packets >= max_packets) or timeout_hit

            if matched_packets == 0:
                print_error("No packets matched current scope filter. Please adjust scope or switch to all traffic.")
                return

            print_info("Extracting metrics...")
            all_metrics = metrics.extract_all_metrics()
            all_metrics["analysis_mode"] = mode
            sampling_mode = "full"
            sampling_confidence = "high"
            if mode == "quick" and (analysis_filter or {}).get("mode") != "all":
                sampling_mode = "adaptive"
                if timeout_hit:
                    sampling_confidence = "low"
                elif limit_hit and max_packets:
                    sampling_confidence = "medium"
                else:
                    sampling_confidence = "high"
            all_metrics["analysis_scope"] = {
                "mode": (analysis_filter or {}).get("mode", "all"),
                "ip": (analysis_filter or {}).get("ip"),
                "ports": Analyzer._normalize_scope_ports((analysis_filter or {}).get("ports")),
                "protocol": (analysis_filter or {}).get("protocol"),
                "time_start": (analysis_filter or {}).get("time_start"),
                "time_end": (analysis_filter or {}).get("time_end"),
                "display_filter": (analysis_filter or {}).get("display_filter"),
                "description": scope_text,
                "input_packets": seen_packets,
                "matched_packets": matched_packets,
                "packet_limit": max_packets,
                "limit_hit": limit_hit,
                "timeout_seconds": timeout_seconds,
                "timeout_hit": timeout_hit,
                "sampling_mode": sampling_mode,
                "sampling_confidence": sampling_confidence,
            }

            if seen_packets > 0 and matched_packets != seen_packets:
                ratio = matched_packets / seen_packets
                print_info(f"Scope hit ratio: {matched_packets}/{seen_packets} ({ratio * 100:.2f}%).")
            if limit_hit and max_packets:
                print_warning(f"Packet limit reached ({max_packets:,}); output may be partial.")
                if mode == "quick" and (analysis_filter or {}).get("mode") != "all":
                    print_warning(
                        "Quick scoped run used adaptive sampling; if this traffic is critical, run deep mode for full confidence."
                    )
            if timeout_hit:
                print_warning("Analysis timeout triggered; diagnostics may be incomplete.")

            print_info("Running anomaly detection...")
            detection_engine = DetectionEngine()
            for rule in get_all_rules():
                detection_engine.register_rule(rule)
            for rule in get_advanced_rules():
                detection_engine.register_rule(rule)
            self._register_plugin_rules(detection_engine)
            anomalies = detection_engine.detect(all_metrics)

            inference_engine = InferenceEngine()
            root_causes = inference_engine.infer(anomalies, all_metrics)

            from diagnosis.deep_inference import DeepInferenceEngine

            deep_engine = DeepInferenceEngine()
            deep_result = deep_engine.analyze(anomalies, all_metrics)

            ai_result = None
            if AIConfig.is_enabled():
                if execution_options is not None:
                    use_ai = bool(execution_options.get("use_ai", False))
                else:
                    use_ai = typer.confirm("AI 已配置，是否启用 AI 分析？", default=True)
                if use_ai:
                    print_info("Calling AI analyzer...")
                    try:
                        from ai.analyzer import AIAnalyzer

                        ai_analyzer = AIAnalyzer()
                        ai_result = ai_analyzer.analyze(
                            all_metrics,
                            anomalies,
                            all_metrics.get("problem_flows", []),
                            analysis_mode=mode,
                            local_result=deep_result,
                        )
                        if ai_result:
                            print_success("AI analysis complete.")
                        else:
                            print_error("AI analysis failed, continue with local result.")
                    except Exception as exc:
                        logger.error(f"AI analysis exception: {exc}")
                        print_error(f"AI analysis exception: {exc}")
                else:
                    print_info("AI analysis skipped by option.")
            else:
                print_info("AI not configured, using local analysis.")

            self._display_results(all_metrics, anomalies, root_causes, ai_result, deep_result)

            if execution_options is not None:
                should_generate_report = bool(execution_options.get("generate_report", True))
                configured_formats = execution_options.get("report_formats") or []
            else:
                should_generate_report = None
                configured_formats = []

            report_gen = ReportGenerator()
            report_files = []
            if mode == "quick":
                if should_generate_report is False:
                    print_info("Report generation skipped by option.")
                else:
                    formats = configured_formats or ["html"]
                    print_info(f"Generating report: {', '.join(formats)}")
                    report_files = report_gen.generate(
                        file_path,
                        all_metrics,
                        anomalies,
                        root_causes,
                        formats,
                        ai_result=ai_result,
                        local_result=deep_result,
                    )
            else:
                if should_generate_report is None:
                    should_generate_report = typer.confirm("Generate report?", default=True)
                if should_generate_report:
                    formats = configured_formats or self.menu.select_report_formats()
                    print_info(f"Generating report: {', '.join(formats)}")
                    report_files = report_gen.generate(
                        file_path,
                        all_metrics,
                        anomalies,
                        root_causes,
                        formats,
                        ai_result=ai_result,
                        local_result=deep_result,
                    )
                else:
                    print_info("Report generation skipped by option.")

            for report_file in report_files:
                print_success(f"Report generated: {report_file}")

            self.menu.history_manager.add_record(
                file_path,
                {
                    "total_packets": all_metrics.get("basic", {}).get("total_packets", 0),
                    "anomalies_count": len(anomalies),
                    "analysis_mode": mode,
                    "retrans_rate": float(all_metrics.get("tcp", {}).get("retrans_rate", 0.0) or 0.0),
                    "rst_rate": float(all_metrics.get("tcp", {}).get("rst_rate", 0.0) or 0.0),
                    "analysis_scope": all_metrics.get("analysis_scope", {}).get("description", "all traffic"),
                    "input_packets": all_metrics.get("analysis_scope", {}).get("input_packets", 0),
                    "matched_packets": all_metrics.get("analysis_scope", {}).get("matched_packets", 0),
                },
            )
            print_success("Analysis completed.")
        except Exception as exc:
            logger.error(f"Analyze failed: {exc}", exc_info=True)
            print_error(f"Analyze failed: {exc}")

    def _display_results(self, metrics: dict, anomalies: list, root_causes: list, ai_result=None, deep_result=None):
        from ui.display import console, print_stats, print_table

        basic = metrics.get("basic", {})
        scope = metrics.get("analysis_scope", {}) or {}
        if scope:
            matched = int(scope.get("matched_packets", 0) or 0)
            seen = int(scope.get("input_packets", matched) or matched)
            ratio_text = f"{(matched / seen * 100):.2f}%" if seen > 0 else "-"
            print_stats(
                {
                    "分析范围": scope.get("description", "全部流量"),
                    "读取包数": seen,
                    "命中过滤": matched,
                    "命中比例": ratio_text,
                },
                "分析范围",
            )
        if basic:
            print_stats(
                {
                    "总包数": basic.get("total_packets", 0),
                    "总字节": f"{basic.get('total_bytes', 0):,}",
                    "持续时间": f"{basic.get('duration', 0):.2f} 秒",
                },
                "基础统计",
            )

        if ai_result:
            console.print(f"\n[bold cyan]AI 深度分析[/bold cyan]\n[bold]{ai_result.summary}[/bold]")
        elif deep_result:
            console.print(f"\n[bold cyan]本地深度分析[/bold cyan]\n[bold]{deep_result.summary}[/bold]")

        protocol = metrics.get("protocol", {})
        if protocol:
            rows = [[proto, count] for proto, count in protocol.items()]
            print_table("传输层协议分布", ["协议", "数量"], rows)

        app_protocol = metrics.get("application_protocol", {})
        if app_protocol:
            rows = [[proto, count] for proto, count in app_protocol.items()]
            print_table("应用层协议分布", ["协议", "数量"], rows)

        tcp = metrics.get("tcp", {})
        if tcp:
            print_stats(
                {
                    "TCP包数": tcp.get("total_tcp", 0),
                    "SYN": tcp.get("syn", 0),
                    "RST": tcp.get("rst", 0),
                    "重传率": f"{tcp.get('retrans_rate', 0) * 100:.2f}%",
                },
                "TCP统计",
            )

        if root_causes:
            console.print("\n[bold cyan]根因分析[/bold cyan]")
            for i, rc in enumerate(root_causes, 1):
                console.print(f"{i}. {rc.name} ({rc.confidence * 100:.0f}%)")

        if anomalies:
            console.print(f"\n[bold yellow]发现异常: {len(anomalies)}[/bold yellow]")
            for anomaly in anomalies:
                console.print(f"- {anomaly.rule_name}: {anomaly.description}")
        else:
            console.print("\n[bold green]未发现明显异常[/bold green]")

    def _show_history(self):
        if not self.menu.history_manager.enabled:
            print_info("History feature is disabled in config.")
            return
        history = self.menu.history_manager.get_recent(10)
        if not history:
            print_info("暂无历史记录")
            return
        from ui.display import print_table

        rows = []
        prev_by_file: Dict[str, Dict[str, Any]] = {}
        for h in history:
            summary = h.get("summary", {}) or {}
            file_key = str(h.get("file_path", "") or "")
            current_anomalies = int(summary.get("anomalies_count", 0) or 0)
            previous = prev_by_file.get(file_key)
            delta_text = "-"
            if previous is not None:
                delta_val = current_anomalies - int(previous.get("anomalies_count", 0) or 0)
                delta_text = f"{delta_val:+d}"
            prev_by_file[file_key] = {"anomalies_count": current_anomalies}
            rows.append(
                [
                    h.get("file_path", ""),
                    h.get("timestamp", ""),
                    summary.get("analysis_scope", "全部流量"),
                    summary.get("anomalies_count", 0),
                    delta_text,
                ]
            )
        print_table("历史记录", ["文件路径", "时间", "分析范围", "异常数", "较上次"], rows)


@app.command()
def interactive():
    """Start interactive mode."""
    if not check_tshark():
        print_error("无法继续，请先安装 Wireshark 或配置 tshark 路径")
        return
    Analyzer().run_interactive()


@app.command()
def analyze(
    file_path: str,
    mode: str = typer.Option("quick", "--mode", help="Analysis mode: quick|deep|diagnosis"),
    scope_ip: Optional[str] = typer.Option(None, "--scope-ip", help="Only analyze packets where src/dst matches this IP"),
    scope_port: Optional[str] = typer.Option(
        None,
        "--scope-port",
        help="Only analyze packets where src/dst port matches (single or comma-separated ports)",
    ),
    scope_protocol: Optional[str] = typer.Option(
        None,
        "--scope-protocol",
        help="Protocol scope: tcp|udp|icmp|arp|dns|http|tls",
    ),
    scope_time_start: Optional[float] = typer.Option(
        None,
        "--scope-time-start",
        help="Relative start time in seconds (frame.time_relative)",
    ),
    scope_time_end: Optional[float] = typer.Option(
        None,
        "--scope-time-end",
        help="Relative end time in seconds (frame.time_relative)",
    ),
    scope_display_filter: Optional[str] = typer.Option(
        None,
        "--scope-display-filter",
        help="Additional tshark display filter expression",
    ),
    all_traffic: bool = typer.Option(False, "--all", help="Analyze all traffic and ignore scope filters"),
    report_formats: str = typer.Option("html", "--report-formats", help="Comma-separated formats: html,markdown,json,all"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI analysis for this run"),
    no_report: bool = typer.Option(False, "--no-report", help="Skip report generation"),
):
    """Analyze one file directly."""
    valid, message = FileValidator.validate_file(file_path)
    if not valid:
        print_error(message)
        raise typer.Exit(code=1)
    if "警告" in message:
        print_warning(message)

    if not check_tshark():
        print_error("\u65e0\u6cd5\u7ee7\u7eed\uff0c\u8bf7\u5148\u5b89\u88c5 Wireshark \u6216\u914d\u7f6e tshark \u8def\u5f84")
        return

    mode = mode.strip().lower()
    if mode not in {"quick", "deep", "diagnosis"}:
        print_error("\u65e0\u6548 mode\uff0c\u53ef\u9009: quick/deep/diagnosis")
        raise typer.Exit(code=1)

    normalized_ip: Optional[str] = None
    if scope_ip:
        normalized_ip = Analyzer._normalize_ip(scope_ip)
        try:
            ipaddress.ip_address(normalized_ip)
        except ValueError:
            print_error("scope-ip \u683c\u5f0f\u9519\u8bef\uff0c\u8bf7\u8f93\u5165\u5408\u6cd5 IPv4/IPv6")
            raise typer.Exit(code=1)

    normalized_ports = Analyzer._normalize_scope_ports(scope_port)
    if scope_port and not normalized_ports:
        print_error("scope-port 格式错误，请输入 1-65535 端口（可逗号分隔）")
        raise typer.Exit(code=1)

    normalized_protocol = Analyzer._normalize_scope_protocol(scope_protocol)
    if scope_protocol and not normalized_protocol:
        print_error("scope-protocol 无效，可选: tcp|udp|icmp|arp|dns|http|tls")
        raise typer.Exit(code=1)

    if scope_time_start is not None and scope_time_start < 0:
        print_error("scope-time-start 不能小于 0")
        raise typer.Exit(code=1)
    if scope_time_end is not None and scope_time_end < 0:
        print_error("scope-time-end 不能小于 0")
        raise typer.Exit(code=1)

    if all_traffic:
        analysis_filter = {"mode": "all", "ip": None}
    else:
        if normalized_ip:
            mode_value = "ip"
        elif normalized_ports or normalized_protocol or scope_display_filter or scope_time_start is not None or scope_time_end is not None:
            mode_value = "custom"
        else:
            mode_value = "all"
        analysis_filter = {
            "mode": mode_value,
            "ip": normalized_ip,
            "ports": normalized_ports,
            "protocol": normalized_protocol,
            "time_start": scope_time_start,
            "time_end": scope_time_end,
            "display_filter": scope_display_filter,
        }

    valid_formats = {"html", "markdown", "json", "all"}
    formats = [item.strip().lower() for item in report_formats.split(",") if item.strip()]
    if not formats:
        formats = ["html"]
    if any(fmt not in valid_formats for fmt in formats):
        print_error("report-formats \u65e0\u6548\uff0c\u53ef\u9009: html,markdown,json,all")
        raise typer.Exit(code=1)
    if "all" in formats:
        formats = ["html", "markdown", "json"]

    Analyzer()._analyze_file(
        file_path,
        mode=mode,
        analysis_filter=analysis_filter,
        execution_options={
            "use_ai": ai,
            "generate_report": not no_report,
            "report_formats": formats,
        },
    )


@app.command()
def setup():
    """Setup tshark path."""
    TSharkFinder.interactive_setup()


if __name__ == "__main__":
    app()
