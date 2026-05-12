"""Project smoke tests for core parser/metrics/report paths."""

import inspect
import sys
from pathlib import Path


def _pass(msg: str):
    print(f"[PASS] {msg}")


def _fail(msg: str):
    print(f"[FAIL] {msg}")


def test_imports() -> bool:
    print("\nTest imports...")
    try:
        from core.parser import PcapParser  # noqa: F401
        from core.metrics import MetricsExtractor  # noqa: F401
        from core.models import PacketInfo, Protocol  # noqa: F401
        from diagnosis.engine import DetectionEngine  # noqa: F401
        from diagnosis.rules import get_all_rules  # noqa: F401
        from report.generator import ReportGenerator  # noqa: F401
        from report.charts import ChartGenerator  # noqa: F401
        from main import analyze  # noqa: F401
        _pass("all core modules import successfully")
        return True
    except Exception as exc:
        _fail(f"import failed: {exc}")
        return False


def test_cli_analyze_args() -> bool:
    print("\nTest CLI args...")
    try:
        from main import analyze

        params = inspect.signature(analyze).parameters
        required = {"mode", "scope_ip", "all_traffic", "report_formats", "ai", "no_report"}
        missing = required - set(params.keys())
        if missing:
            raise AssertionError(f"missing args: {sorted(missing)}")
        _pass("CLI analyze args are available")
        return True
    except Exception as exc:
        _fail(f"CLI args check failed: {exc}")
        return False


def test_parser_payload_fallback_fields() -> bool:
    print("\nTest parser payload fallback fields...")
    try:
        from types import SimpleNamespace

        from core.parser import PcapParser

        parser = PcapParser("dummy.pcap")

        pkt_tcp_segment = SimpleNamespace(
            tcp=SimpleNamespace(segment_data="47:45:54:20:2f:20:48:54:54:50"),
            layers=[],
        )
        if parser._extract_tcp_payload_hex(pkt_tcp_segment) != "474554202f2048545450":
            raise AssertionError("failed to parse tcp.segment_data payload")

        pkt_data_layer = SimpleNamespace(
            tcp=SimpleNamespace(),
            data=SimpleNamespace(data="48:54:54:50:2f:31:2e:31"),
            layers=[],
        )
        if parser._extract_tcp_payload_hex(pkt_data_layer) != "485454502f312e31":
            raise AssertionError("failed to parse data.data payload")

        pkt_non_hex = SimpleNamespace(
            tcp=SimpleNamespace(payload="HTTP/1.1 200 OK"),
            layers=[],
        )
        if parser._extract_tcp_payload_hex(pkt_non_hex):
            raise AssertionError("non-hex text should not be treated as payload hex")

        parser._tshark_payload_map_attempted = True
        parser._tshark_payload_map = {123: "68656c6c6f"}
        pkt_tshark_only = SimpleNamespace(
            number=123,
            sniff_timestamp=0.1,
            length=64,
            tcp=SimpleNamespace(
                srcport="50000",
                dstport="80",
                flags="0x0018",
                len="5",
                stream="9",
            ),
            layers=[],
        )
        info = parser._extract_packet_info(pkt_tshark_only)
        if not info or info.tcp_payload_hex != "68656c6c6f":
            raise AssertionError("failed to fill payload from tshark fallback map")

        _pass("parser payload extraction supports fallback fields")
        return True
    except Exception as exc:
        _fail(f"parser payload fallback test failed: {exc}")
        return False


def test_ai_response_parser() -> bool:
    print("\nTest AI response parser...")
    try:
        from ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer()
        json_response = """
        {
          "summary": "核心网络连接异常",
          "root_cause": "目标端口未响应SYN",
          "affected_systems": ["10.1.1.1:50000 -> 10.1.1.2:443"],
          "troubleshooting_steps": ["1. 检查监听", "2. 检查防火墙"],
          "prevention": ["加监控", "优化告警"],
          "risk_level": "high",
          "confidence": "87%"
        }
        """
        parsed = analyzer._parse_response(json_response)
        if parsed.risk_level != "高":
            raise AssertionError(f"risk_level parse failed: {parsed.risk_level}")
        if abs(parsed.confidence - 0.87) > 1e-6:
            raise AssertionError(f"confidence parse failed: {parsed.confidence}")
        if not parsed.affected_systems:
            raise AssertionError("affected_systems should not be empty")

        fenced_response = """```json
        {"summary":"fenced","root_cause":"ok","affected_systems":[],"troubleshooting_steps":[],"prevention":[],"risk_level":"低","confidence":0.6}
        ```"""
        fenced = analyzer._parse_response(fenced_response)
        if fenced.summary != "fenced":
            raise AssertionError("failed to parse fenced JSON payload")
        if fenced.risk_level != "低":
            raise AssertionError("failed to normalize fenced risk_level")

        fallback_response = """
        核心问题
        出口链路异常抖动
        根本原因
        - RTT 波动超阈值
        风险等级: 中
        置信度: 65%
        """
        fallback = analyzer._parse_response(fallback_response)
        if fallback.risk_level != "中":
            raise AssertionError("fallback parser risk level failed")
        if abs(fallback.confidence - 0.65) > 1e-6:
            raise AssertionError("fallback parser confidence failed")

        _pass("AI parser supports JSON-first and fallback parsing")
        return True
    except Exception as exc:
        _fail(f"AI parser test failed: {exc}")
        return False


def test_metrics_timeline_topology_stream() -> bool:
    print("\nTest timeline/topology/follow-stream metrics...")
    try:
        from core.metrics import MetricsExtractor
        from core.models import PacketInfo, Protocol

        extractor = MetricsExtractor()
        packets = [
            PacketInfo(
                number=1,
                timestamp=0.0,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=51000,
                dst_port=80,
                protocol=Protocol.TCP,
                transport_protocol=Protocol.TCP,
                length=66,
                tcp_flags="0x0002",
                tcp_seq=1000,
                tcp_stream_id=5,
            ),
            PacketInfo(
                number=2,
                timestamp=0.05,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                src_port=80,
                dst_port=51000,
                protocol=Protocol.TCP,
                transport_protocol=Protocol.TCP,
                length=66,
                tcp_flags="0x0012",
                tcp_seq=2000,
                tcp_stream_id=5,
            ),
            PacketInfo(
                number=3,
                timestamp=0.09,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=51000,
                dst_port=80,
                protocol=Protocol.TCP,
                transport_protocol=Protocol.TCP,
                length=54,
                tcp_flags="0x0010",
                tcp_seq=1001,
                tcp_stream_id=5,
            ),
            PacketInfo(
                number=4,
                timestamp=0.20,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=51000,
                dst_port=80,
                protocol=Protocol.TCP,
                transport_protocol=Protocol.TCP,
                application_protocol=Protocol.HTTP,
                length=180,
                tcp_flags="0x0018",
                tcp_seq=1001,
                tcp_stream_id=5,
                tcp_payload_hex="474554202f20485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a0d0a",
            ),
            PacketInfo(
                number=5,
                timestamp=0.38,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                src_port=80,
                dst_port=51000,
                protocol=Protocol.TCP,
                transport_protocol=Protocol.TCP,
                application_protocol=Protocol.HTTP,
                length=220,
                tcp_flags="0x0018",
                tcp_seq=2001,
                tcp_stream_id=5,
                tcp_payload_hex="485454502f312e3120323030204f4b0d0a436f6e74656e742d4c656e6774683a20350d0a0d0a48656c6c6f",
            ),
            PacketInfo(
                number=6,
                timestamp=0.48,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.1",
                src_port=80,
                dst_port=51000,
                protocol=Protocol.TCP,
                transport_protocol=Protocol.TCP,
                length=120,
                tcp_flags="0x0018",
                tcp_seq=2001,
                tcp_stream_id=5,
                tcp_payload_hex="48656c6c6f",
                is_retransmission=True,
            ),
            PacketInfo(
                number=7,
                timestamp=1.0,
                src_ip="10.0.0.3",
                dst_ip="10.0.0.53",
                src_port=53000,
                dst_port=53,
                protocol=Protocol.UDP,
                transport_protocol=Protocol.UDP,
                application_protocol=Protocol.DNS,
                length=88,
            ),
            PacketInfo(
                number=8,
                timestamp=1.4,
                src_ip="10.0.0.4",
                dst_ip="10.0.0.5",
                src_port=52001,
                dst_port=443,
                protocol=Protocol.TCP,
                transport_protocol=Protocol.TCP,
                length=74,
                tcp_flags="0x0002",
                tcp_seq=3000,
            ),
        ]

        for pkt in packets:
            extractor.add_packet(pkt)

        metrics = extractor.extract_all_metrics()

        timeline = metrics.get("traffic_timeline", {})
        if int(timeline.get("point_count", 0) or 0) <= 0:
            raise AssertionError("traffic_timeline has no points")

        topology = metrics.get("ip_topology", {})
        if int(topology.get("node_count", 0) or 0) < 2:
            raise AssertionError("ip_topology node_count invalid")
        if int(topology.get("edge_count", 0) or 0) < 1:
            raise AssertionError("ip_topology edge_count invalid")

        tcp = metrics.get("tcp", {})
        if int(tcp.get("connection_attempts", 0) or 0) != 2:
            raise AssertionError(f"connection_attempts mismatch: {tcp.get('connection_attempts')}")
        if int(tcp.get("connection_failures", 0) or 0) != 1:
            raise AssertionError(f"connection_failures mismatch: {tcp.get('connection_failures')}")
        success_rate = float(tcp.get("connection_success_rate", 0) or 0)
        if abs(success_rate - 0.5) > 1e-6:
            raise AssertionError(f"connection_success_rate mismatch: {success_rate}")

        _pass("timeline/topology metrics are available")
        return True
    except Exception as exc:
        _fail(f"metrics test failed: {exc}")
        return False


def test_advanced_rules_new_signals() -> bool:
    print("\nTest advanced rules for ARP/leak/burst...")
    try:
        from diagnosis.advanced_rules import ARPAnomalyRule, ConnectionLeakRule, TrafficBurstRule

        arp_metrics = {
            "basic": {"duration": 20.0},
            "network": {
                "arp_total": 420,
                "arp_ip_mac_conflicts": 1,
                "arp_conflict_examples": ["10.0.0.10 -> aa:aa:aa:aa:aa:aa, bb:bb:bb:bb:bb:bb"],
            },
            "protocol": {"ARP": 420},
            "traffic_timeline": {
                "window_seconds": 10.0,
                "series": [
                    {"index": 0, "time_s": 0.0, "arp_packets": 220},
                    {"index": 1, "time_s": 10.0, "arp_packets": 200},
                ],
            },
        }
        if not ARPAnomalyRule().check(arp_metrics):
            raise AssertionError("ARPAnomalyRule should trigger")

        leak_metrics = {
            "tcp": {"connection_leak_flows": 2},
            "problem_flows": [
                {
                    "src_ip": "10.0.0.1",
                    "src_port": 52000,
                    "dst_ip": "10.0.0.2",
                    "dst_port": 8080,
                    "issues": ["连接疑似泄漏：已持续 180.0s 且未见 FIN/RST 关闭"],
                    "packet_count": 80,
                    "duration_s": 180.0,
                }
            ],
            "flow_analysis": {"flows": {}},
        }
        if not ConnectionLeakRule().check(leak_metrics):
            raise AssertionError("ConnectionLeakRule should trigger")

        burst_metrics = {
            "traffic_timeline": {
                "window_seconds": 10.0,
                "series": [
                    {"index": 0, "time_s": 0.0, "packets_per_sec": 10.0, "throughput_mbps": 0.5, "tcp_packets": 80, "udp_packets": 20, "arp_packets": 0},
                    {"index": 1, "time_s": 10.0, "packets_per_sec": 12.0, "throughput_mbps": 0.6, "tcp_packets": 90, "udp_packets": 25, "arp_packets": 0},
                    {"index": 2, "time_s": 20.0, "packets_per_sec": 180.0, "throughput_mbps": 8.5, "tcp_packets": 1400, "udp_packets": 200, "arp_packets": 10},
                    {"index": 3, "time_s": 30.0, "packets_per_sec": 11.0, "throughput_mbps": 0.7, "tcp_packets": 85, "udp_packets": 20, "arp_packets": 0},
                ]
            }
        }
        if not TrafficBurstRule().check(burst_metrics):
            raise AssertionError("TrafficBurstRule should trigger")

        _pass("advanced rules detect ARP/leak/burst signals")
        return True
    except Exception as exc:
        _fail(f"advanced rules new signals test failed: {exc}")
        return False


def test_config_get_none_semantics() -> bool:
    print("\nTest config getter None semantics...")
    try:
        from utils.config import Config

        cfg = Config("config.yaml")
        cfg._config = {"a": {"b": None, "c": 1}}

        if cfg.get("a.b", "fallback") is not None:
            raise AssertionError("expected explicit None value, got default fallback")
        if cfg.get("a.c", 0) != 1:
            raise AssertionError("expected normal key lookup value")
        if cfg.get("a.missing", "fallback") != "fallback":
            raise AssertionError("expected fallback for missing key")

        _pass("config getter distinguishes None and missing keys")
        return True
    except Exception as exc:
        _fail(f"config getter test failed: {exc}")
        return False


def test_report_sections() -> bool:
    print("\nTest report sections/charts...")
    try:
        from core.metrics import MetricsExtractor
        from core.models import PacketInfo, Protocol
        from report.generator import ReportGenerator

        extractor = MetricsExtractor()
        extractor.add_packet(
            PacketInfo(
                number=1,
                timestamp=0.0,
                src_ip="10.1.1.1",
                dst_ip="10.1.1.2",
                src_port=50000,
                dst_port=80,
                protocol=Protocol.TCP,
                transport_protocol=Protocol.TCP,
                length=150,
                tcp_flags="0x0018",
                tcp_seq=1,
                tcp_stream_id=1,
                tcp_payload_hex="474554202f0d0a0d0a",
            )
        )
        metrics = extractor.extract_all_metrics()

        gen = ReportGenerator(output_dir="reports")
        data = gen._prepare_data("demo.pcap", metrics, [], [], None, None)
        charts = gen._generate_charts(metrics)

        if not charts.get("traffic_timeline"):
            raise AssertionError("traffic_timeline chart missing")
        if not charts.get("ip_topology"):
            raise AssertionError("ip_topology chart missing")
        if data.get("follow_streams"):
            raise AssertionError("follow_streams should be disabled")

        files = gen.generate("demo.pcap", metrics, [], [], ["html"])
        if not files:
            raise AssertionError("HTML report not generated")

        html_path = Path(files[0])
        html = html_path.read_text(encoding="utf-8", errors="ignore")
        if "TCP 会话还原（Follow Stream）" in html:
            raise AssertionError("Follow Stream HTML section should be removed")

        _pass("report sections/charts are generated")
        return True
    except Exception as exc:
        _fail(f"report section test failed: {exc}")
        return False


def main() -> int:
    tests = [
        test_imports,
        test_cli_analyze_args,
        test_parser_payload_fallback_fields,
        test_ai_response_parser,
        test_metrics_timeline_topology_stream,
        test_advanced_rules_new_signals,
        test_config_get_none_semantics,
        test_report_sections,
    ]
    passed = 0
    for fn in tests:
        if fn():
            passed += 1

    print("\n" + "=" * 60)
    print(f"Smoke Result: {passed}/{len(tests)} passed")
    print("=" * 60)
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main())
