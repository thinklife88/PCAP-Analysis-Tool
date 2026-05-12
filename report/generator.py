"""Report generation module."""

import hashlib
import json
import re
import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from diagnosis.engine import Anomaly
from diagnosis.inference import RootCause
from utils.config import get_config
from utils.logger import setup_logger

logger = setup_logger()


class ReportGenerator:
    """Generate PCAP analysis reports in HTML/Markdown/JSON formats."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.template_dir = Path(__file__).resolve().parent / "templates"
        self.jinja_env: Optional[Environment] = None
        if self.template_dir.exists():
            self.jinja_env = Environment(
                loader=FileSystemLoader(str(self.template_dir)),
                autoescape=select_autoescape(["html", "xml"]),
            )

    def generate(
        self,
        file_path: str,
        metrics: Dict[str, Any],
        anomalies: List[Anomaly],
        root_causes: List[RootCause],
        formats: List[str],
        ai_result=None,
        local_result=None,
    ) -> List[str]:
        """Generate reports in selected formats."""
        generated_files: List[str] = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = Path(file_path).stem

        report_data = self._prepare_data(
            file_path,
            metrics,
            anomalies,
            root_causes,
            ai_result=ai_result,
            local_result=local_result,
        )
        report_data["charts"] = self._generate_charts(metrics)
        if "html" in formats:
            generated_files.append(self._generate_html(report_data, base_name, timestamp))
        if "markdown" in formats:
            generated_files.append(self._generate_markdown(report_data, base_name, timestamp))
        if "json" in formats:
            generated_files.extend(self._generate_json(report_data, base_name, timestamp))
        return generated_files

    def _generate_charts(self, metrics: Dict[str, Any]) -> Dict[str, str]:
        try:
            from report.charts import ChartGenerator
        except Exception as exc:
            logger.warning(f"Chart module import failed, continue without charts: {exc}")
            return {}

        chart_builders = {
            "plotly_loader": ChartGenerator.generate_plotly_loader,
            "protocol_pie": ChartGenerator.generate_protocol_pie,
            "app_protocol_pie": ChartGenerator.generate_application_protocol_pie,
            "top_ips_bar": ChartGenerator.generate_top_ips_bar,
            "tcp_metrics_bar": ChartGenerator.generate_tcp_metrics_bar,
            "traffic_timeline": ChartGenerator.generate_traffic_timeline,
            "rtt_timeline": ChartGenerator.generate_rtt_timeline,
            "asymmetry_bar": ChartGenerator.generate_asymmetry_bar,
            "ip_topology": ChartGenerator.generate_ip_topology,
            "flow_fault_timeline": ChartGenerator.generate_flow_fault_timeline,
        }

        charts: Dict[str, str] = {}
        for key, builder in chart_builders.items():
            try:
                charts[key] = str(builder(metrics) or "")
            except Exception as exc:
                logger.warning(f"Chart generation failed for {key}: {exc}")
                charts[key] = ""
        return charts

    def _prepare_data(
        self,
        file_path: str,
        metrics: Dict[str, Any],
        anomalies: List[Anomaly],
        root_causes: List[RootCause],
        ai_result=None,
        local_result=None,
    ) -> Dict[str, Any]:
        basic = metrics.get("basic", {}) or {}
        mode_key = str(metrics.get("analysis_mode") or metrics.get("mode") or "local").lower()
        mode_label = self._mode_label(mode_key)

        scope = metrics.get("analysis_scope", {}) or {}
        scope_mode = str(scope.get("mode") or "all").lower()
        scope_ip = scope.get("ip")
        scope_desc = scope.get("description") or "all traffic"
        scope_input = int(scope.get("input_packets", basic.get("total_packets", 0)) or 0)
        scope_matched = int(scope.get("matched_packets", basic.get("total_packets", 0)) or 0)
        scope_ratio = (scope_matched / scope_input) if scope_input > 0 else 0.0
        output_level = self._output_level(mode_key)

        anomaly_dicts = [self._anomaly_to_dict(a, metrics) for a in anomalies]
        root_cause_dicts = [self._root_cause_to_dict(rc) for rc in root_causes]
        prioritized_actions = self._dedupe_prioritized_actions(
            self._build_prioritized_actions(metrics, root_cause_dicts, anomaly_dicts)
        )
        fault_limit = {3: 6, 4: 10, 5: 15}.get(output_level, 6)
        flow_limit = {3: 12, 4: 24, 5: 40}.get(output_level, 12)
        fault_locations = self._build_fault_locations(metrics, anomaly_dicts, limit=fault_limit)
        flow_interactions = self._build_flow_interactions(metrics, limit=flow_limit, output_level=output_level)
        fault_flow_details = self._build_fault_flow_details(metrics, limit=flow_limit)
        command_checklist = self._build_command_checklist(
            metrics,
            anomaly_dicts,
            fault_locations,
            prioritized_actions=prioritized_actions,
            output_level=output_level,
        )
        regression_checks = self._build_regression_checks(metrics, output_level=output_level)
        resolution_plan = self._build_resolution_plan(prioritized_actions, output_level=output_level)
        management_summary = self._build_management_summary(
            metrics,
            anomaly_dicts,
            fault_locations,
            prioritized_actions,
        )
        primary_issue = self._infer_primary_issue(metrics, anomaly_dicts, fault_locations)
        incident_snapshot = self._build_incident_snapshot(
            metrics,
            anomaly_dicts,
            fault_locations,
            management_summary,
            primary_issue=primary_issue,
        )
        key_metric_rows = self._build_key_metric_rows(metrics)
        timeline_insights = self._build_timeline_insights(metrics, limit=8 if output_level >= 4 else 5)
        decision_tree = self._build_decision_tree(metrics, anomaly_dicts, fault_locations)
        pmtu_samples = self._build_mtu_impact_samples(metrics, limit=6 if output_level >= 4 else 4)
        chart_fallback_summary = self._build_chart_fallback_summary(metrics)
        history_trend = self._build_history_trend(file_path, metrics, anomaly_dicts)
        report_profile = self._build_report_profile(anomaly_dicts, root_cause_dicts)
        mode_brief = self._build_mode_brief(
            mode_key,
            metrics,
            anomaly_dicts,
            fault_locations,
            report_profile=report_profile,
        )
        smart_findings = self._build_smart_findings(
            metrics,
            anomaly_dicts,
            root_cause_dicts,
            fault_locations,
            report_profile,
            history_trend=history_trend,
        )
        secondary_actions = self._build_secondary_actions(
            prioritized_actions,
            management_summary.get("top_actions", []),
        )
        diagnosis_casebook = (
            self._build_diagnosis_casebook(
                metrics,
                anomaly_dicts,
                fault_locations,
                prioritized_actions,
                limit=12,
            )
            if output_level >= 5
            else []
        )
        acceptance_checklist = (
            self._build_acceptance_checklist(
                metrics,
                anomaly_dicts,
                fault_locations,
            )
            if output_level >= 5
            else []
        )
        report_fingerprint = self._build_report_fingerprint(
            file_path=file_path,
            mode_key=mode_key,
            scope_mode=scope_mode,
            scope_ip=str(scope_ip or ""),
            basic=basic,
        )
        quick_action_card = self._build_quick_action_card(
            incident_snapshot=incident_snapshot,
            management_summary=management_summary,
            command_checklist=command_checklist,
            regression_checks=regression_checks,
            key_metric_rows=key_metric_rows,
        )
        anomaly_groups = self._build_anomaly_groups(
            anomaly_dicts,
            root_cause_dicts,
            fault_flow_details,
        )
        confidence_explainer = self._build_confidence_explainer(
            metrics=metrics,
            anomalies=anomaly_dicts,
            root_causes=root_cause_dicts,
            report_profile=report_profile,
            primary_issue=primary_issue,
        )
        blind_spots = self._build_blind_spots(
            metrics=metrics,
            anomalies=anomaly_dicts,
            root_causes=root_cause_dicts,
            scope_ratio=scope_ratio,
        )
        report_diff = self._build_report_diff(
            history_trend=history_trend,
            metrics=metrics,
            anomalies=anomaly_dicts,
        )
        business_impact = self._build_business_impact(
            metrics=metrics,
            anomalies=anomaly_dicts,
            fault_locations=fault_locations,
        )
        closure_score = self._build_closure_score(
            regression_checks=regression_checks,
            acceptance_checklist=acceptance_checklist,
        )
        evidence_traces = self._build_evidence_traces(
            metrics=metrics,
            anomalies=anomaly_dicts,
            fault_flow_details=fault_flow_details,
            timeline_insights=timeline_insights,
            limit=18 if output_level >= 4 else 12,
        )
        lightweight_mode_default = self._lightweight_mode_default(mode_key)
        chart_segments = self._build_chart_segments(lightweight_mode_default)
        health_score = self._build_health_score(
            metrics=metrics,
            anomalies=anomaly_dicts,
            fault_locations=fault_locations,
            key_metric_rows=key_metric_rows,
            management_summary=management_summary,
            business_impact=business_impact,
        )
        attachments = self._build_attachments(
            file_path=file_path,
            metrics=metrics,
            anomalies=anomaly_dicts,
            root_causes=root_cause_dicts,
            output_level=output_level,
        )

        raw_local_result = self._analysis_result_to_dict(local_result) if local_result else {
            "summary": "No explicit local summary",
            "root_cause": "",
            "risk_level": "UNKNOWN",
            "confidence": 0.0,
        }

        pcap_start = float(basic.get("start_time", 0) or 0)
        pcap_end = float(basic.get("end_time", 0) or 0)
        if pcap_start > 0:
            pcap_start_str = datetime.fromtimestamp(pcap_start).strftime("%Y-%m-%d %H:%M:%S")
            pcap_end_str = datetime.fromtimestamp(pcap_end).strftime("%Y-%m-%d %H:%M:%S") if pcap_end > 0 else "—"
            pcap_time_range = f"{pcap_start_str} ~ {pcap_end_str}"
        else:
            pcap_time_range = ""

        data = {
            "file_path": file_path,
            "file_name": Path(file_path).name,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "pcap_time_range": pcap_time_range,
            "mode_key": mode_key,
            "mode_label": mode_label,
            "output_level": output_level,
            "total_packets": int(basic.get("total_packets", 0) or 0),
            "duration": float(basic.get("duration", 0) or 0),
            "total_bytes": int(basic.get("total_bytes", 0) or 0),
            "analysis_scope_mode": scope_mode,
            "analysis_scope_ip": scope_ip,
            "analysis_scope_desc": scope_desc,
            "analysis_scope_input_packets": scope_input,
            "analysis_scope_matched_packets": scope_matched,
            "analysis_scope_ratio": scope_ratio,
            "metrics": metrics,
            "anomalies": anomaly_dicts,
            "root_causes": root_cause_dicts,
            "has_issues": len(anomaly_dicts) > 0,
            "ai_result": self._analysis_result_to_dict(ai_result) if ai_result else None,
            "local_result": raw_local_result,
            "is_ai": ai_result is not None,
            "top_issue": self._pick_top_issue(metrics, anomaly_dicts, fault_locations),
            "primary_issue": primary_issue,
            "key_metrics": self._extract_key_metrics(metrics),
            "prioritized_actions": prioritized_actions,
            "fault_locations": fault_locations,
            "flow_interactions": flow_interactions,
            "fault_flow_details": fault_flow_details,
            # Follow Stream is intentionally disabled per product decision.
            "follow_streams": [],
            "command_checklist": command_checklist,
            "regression_checks": regression_checks if output_level >= 4 else [],
            "resolution_plan": resolution_plan if output_level >= 4 else [],
            "diagnosis_casebook": diagnosis_casebook,
            "acceptance_checklist": acceptance_checklist,
            "management_summary": management_summary,
            "report_profile": report_profile,
            "smart_findings": smart_findings,
            "incident_snapshot": incident_snapshot,
            "key_metric_rows": key_metric_rows,
            "timeline_insights": timeline_insights,
            "decision_tree": decision_tree,
            "pmtu_samples": pmtu_samples,
            "chart_fallback_summary": chart_fallback_summary,
            "history_trend": history_trend,
            "mode_brief": mode_brief,
            "secondary_actions": secondary_actions,
            "show_prioritized_actions": bool(secondary_actions),
            "quick_action_card": quick_action_card,
            "evidence_traces": evidence_traces,
            "anomaly_groups": anomaly_groups,
            "confidence_explainer": confidence_explainer,
            "blind_spots": blind_spots,
            "report_diff": report_diff,
            "business_impact": business_impact,
            "closure_score": closure_score,
            "attachments": attachments,
            "report_fingerprint": report_fingerprint,
            "lightweight_mode_default": lightweight_mode_default,
            "chart_segments": chart_segments,
            "health_score": health_score,
            "charts": {},
        }
        if not data["local_result"].get("summary"):
            data["local_result"] = self._build_local_result_fallback(data)
        data["local_result"] = self._build_local_result_smart(data)
        return data

    @staticmethod
    def _output_level(mode_key: str) -> int:
        if mode_key == "diagnosis":
            return 5
        if mode_key == "deep":
            return 4
        return 3

    @staticmethod
    def _mode_label(mode_key: str) -> str:
        return {
            "quick": "快速分析",
            "deep": "深度分析",
            "diagnosis": "故障诊断",
            "local": "本地分析",
        }.get(mode_key, "本地分析")

    @staticmethod
    def _build_report_fingerprint(
        file_path: str,
        mode_key: str,
        scope_mode: str,
        scope_ip: str,
        basic: Dict[str, Any],
    ) -> str:
        normalized = str(file_path or "").replace("\\", "/").lower()
        seed = "|".join(
            [
                normalized,
                str(mode_key or "").lower(),
                str(scope_mode or "").lower(),
                str(scope_ip or "").strip(),
                str(int(basic.get("total_packets", 0) or 0)),
                f"{float(basic.get('duration', 0.0) or 0.0):.6f}",
                f"{float(basic.get('start_time', 0.0) or 0.0):.6f}",
            ]
        )
        return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:20]

    @staticmethod
    def _lightweight_mode_default(mode_key: str) -> bool:
        try:
            cfg_mode = get_config().get("report.lightweight_mode_default", None)
        except Exception:
            cfg_mode = None
        if cfg_mode is None:
            return str(mode_key or "").lower() == "quick"
        if isinstance(cfg_mode, bool):
            return cfg_mode
        return str(cfg_mode).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _build_chart_segments(lightweight_mode_default: bool) -> List[Dict[str, Any]]:
        return [
            {
                "id": "seg_core",
                "title": "核心分布",
                "description": "协议、Top IP 与 TCP 关键指标",
                "keys": ["protocol_pie", "app_protocol_pie", "top_ips_bar", "tcp_metrics_bar"],
                "default_visible": True,
            },
            {
                "id": "seg_timeline",
                "title": "时序质量",
                "description": "流量、RTT 与不对称趋势",
                "keys": ["traffic_timeline", "rtt_timeline", "asymmetry_bar"],
                "default_visible": not lightweight_mode_default,
            },
            {
                "id": "seg_topology",
                "title": "拓扑与故障",
                "description": "IP 通信拓扑与故障泳道",
                "keys": ["ip_topology", "flow_fault_timeline"],
                "default_visible": not lightweight_mode_default,
            },
        ]

    @staticmethod
    def _analysis_result_to_dict(result: Any) -> Dict[str, Any]:
        return {
            "summary": getattr(result, "summary", ""),
            "root_cause": getattr(result, "root_cause", ""),
            "affected_systems": getattr(result, "affected_systems", []),
            "troubleshooting_steps": getattr(result, "troubleshooting_steps", []),
            "prevention": getattr(result, "prevention", []),
            "risk_level": getattr(result, "risk_level", ""),
            "confidence": float(getattr(result, "confidence", 0.0) or 0.0),
        }

    @staticmethod
    def _severity_score(severity_name: str) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(severity_name or "").upper(), 0)

    @staticmethod
    def _severity_label(severity_name: str) -> str:
        return {
            "CRITICAL": "严重",
            "HIGH": "高",
            "MEDIUM": "中",
            "LOW": "低",
        }.get(str(severity_name or "").upper(), "未知")

    @staticmethod
    def _normalize_text(text: str) -> str:
        return re.sub(r"[\s\W_]+", "", str(text or "").lower())

    @classmethod
    def _dedupe_strings(cls, items: List[str], limit: int = 0) -> List[str]:
        result: List[str] = []
        seen = set()
        for item in items or []:
            text = str(item or "").strip()
            if not text:
                continue
            key = cls._normalize_text(text)
            if key in seen:
                continue
            seen.add(key)
            result.append(text)
            if limit > 0 and len(result) >= limit:
                break
        return result

    @staticmethod
    def _extract_thresholds() -> Dict[str, Any]:
        try:
            return get_config().get("analysis.thresholds", {}) or {}
        except Exception:
            return {}

    @staticmethod
    def _domain_label(text: str) -> str:
        upper = str(text or "").upper()
        if any(k in upper for k in ["DNS", "HTTP", "TLS", "应用", "TTFB"]):
            return "应用"
        if any(k in upper for k in ["ICMP", "FRAG", "分片", "长度异常", "PMTU", "MTU", "路由", "广播", "组播", "对称"]):
            return "网络"
        if any(k in upper for k in ["SYN", "握手", "RST", "重传", "ACK", "窗口", "TCP", "UDP"]):
            return "传输"
        return "综合"

    def _anomaly_to_dict(self, anomaly: Anomaly, metrics: Dict[str, Any]) -> Dict[str, Any]:
        severity_name = getattr(getattr(anomaly, "severity", None), "name", "UNKNOWN")
        rule_name = str(getattr(anomaly, "rule_name", "") or "")
        evidence = self._dedupe_strings([ev for ev in getattr(anomaly, "evidence", []) if ev], limit=12)
        domain = self._domain_label(f"{rule_name} {getattr(anomaly, 'description', '') or ''}")
        tags = self._extract_signal_tags(rule_name, str(getattr(anomaly, "description", "") or ""), " ".join(evidence[:4]))
        signature_seed = f"{rule_name}|{str(getattr(anomaly, 'description', '') or '')}"
        signature = hashlib.sha1(signature_seed.encode("utf-8")).hexdigest()[:12]
        return {
            "rule_name": rule_name,
            "severity_name": severity_name,
            "severity": self._severity_label(severity_name),
            "description": str(getattr(anomaly, "description", "") or ""),
            "evidence": evidence,
            "count": int(getattr(anomaly, "count", 0) or 0),
            "threshold_rows": self._threshold_rows(rule_name, metrics),
            "suggestions": self._dedupe_strings(self._suggest_for_anomaly(rule_name, metrics), limit=6),
            "domain": domain,
            "tags": tags,
            "tag_keys": ",".join(tags),
            "signature": signature,
        }

    def _threshold_rows(self, rule_name: str, metrics: Dict[str, Any]) -> List[Dict[str, str]]:
        cfg = metrics.get("config_thresholds") or self._extract_thresholds()
        tcp = metrics.get("tcp", {}) or {}
        perf = metrics.get("performance", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}
        udp = metrics.get("udp", {}) or {}
        rows: List[Dict[str, str]] = []
        raw = str(rule_name or "")
        upper = raw.upper()

        def has_any(keys: List[str]) -> bool:
            return any(k in raw or k in upper for k in keys)

        def add(metric: str, actual: str, threshold: str, exceeded: bool):
            rows.append(
                {
                    "metric": metric,
                    "actual": actual,
                    "threshold": threshold,
                    "status": "超阈值" if exceeded else "正常",
                    "status_class": "status-bad" if exceeded else "status-good",
                }
            )

        if has_any(["重传", "RETRANS"]):
            val = float(tcp.get("retrans_rate", 0) or 0)
            th = float(cfg.get("retransmission_rate", 0.05))
            add("TCP 重传率", f"{val * 100:.2f}%", f">{th * 100:.2f}%", val > th)

        if has_any(["重置", "RST"]):
            val = float(tcp.get("rst_rate", 0) or 0)
            th = float(cfg.get("rst_rate", 0.02))
            add("TCP RST率", f"{val * 100:.2f}%", f">{th * 100:.2f}%", val > th)

        if has_any(["延迟", "卡慢", "RTT", "JITTER", "抖动"]):
            max_gap = float(perf.get("max_interval", 0) or 0)
            max_gap_th = float(cfg.get("max_interval_s", 5.0))
            add("最大包间隔", f"{max_gap:.2f}s", f">{max_gap_th:.2f}s", max_gap > max_gap_th)

            max_rtt_ms = float(tcp.get("max_rtt", 0) or 0) * 1000
            rtt_th = float(cfg.get("rtt_high_ms", cfg.get("rtt_threshold_ms", 500)))
            add("最大RTT", f"{max_rtt_ms:.0f}ms", f">{rtt_th:.0f}ms", max_rtt_ms > rtt_th)

        if has_any(["DNS"]):
            dns_total = max(int(app.get("dns_total", 0) or 0), 1)
            dns_rate = float(app.get("dns_error_rcode", 0) or 0) / dns_total
            dns_th = float(cfg.get("dns_failure_rate", 0.05))
            add("DNS 失败率", f"{dns_rate * 100:.2f}%", f">{dns_th * 100:.2f}%", dns_rate > dns_th)

        if has_any(["HTTP"]):
            http_total = max(int(app.get("http_total", 0) or 0), 1)
            http_rate = float(app.get("http_error_responses", 0) or 0) / http_total
            http_th = float(cfg.get("http_error_rate", 0.1))
            add("HTTP 错误率", f"{http_rate * 100:.2f}%", f">{http_th * 100:.2f}%", http_rate > http_th)

        if has_any(["TLS"]):
            alerts = int(app.get("tls_alerts", 0) or 0)
            add("TLS Alert数", str(alerts), ">0", alerts > 0)

        if has_any(["半开", "HALF_OPEN"]):
            half_open = int(tcp.get("half_open_flows", 0) or 0)
            half_open_th = int(cfg.get("half_open_flows", 50))
            add("TCP 半开连接流数", str(half_open), f">{half_open_th}", half_open > half_open_th)

        if has_any(["对称", "ASYMMETRY"]):
            asym = float(net.get("asymmetry_ratio", 1) or 1)
            asym_th = float(cfg.get("asymmetry_ratio", 10))
            add("流量不对称比", f"{asym:.1f}:1", f">{asym_th:.1f}:1", asym > asym_th)

        if has_any(["广播", "组播", "BROADCAST"]):
            rate = float(net.get("broadcast_rate", 0) or 0)
            rate_th = float(cfg.get("broadcast_rate", 1000))
            add("广播/组播速率", f"{rate:.1f} pkt/s", f">{rate_th:.1f} pkt/s", rate > rate_th)

        if has_any(["UDP无响应", "UDP 无响应", "NO_RESPONSE"]):
            no_resp = int(udp.get("no_response_flows", 0) or 0)
            add("UDP无响应流数", str(no_resp), ">0", no_resp > 0)

        if has_any(["ICMP", "不可达", "UNREACHABLE"]):
            unreachable = int(net.get("icmp_unreachable", 0) or 0)
            add("ICMP不可达报文", str(unreachable), ">0", unreachable > 0)

        return rows

    def _suggest_for_anomaly(self, rule_name: str, metrics: Dict[str, Any]) -> List[str]:
        _ = metrics
        raw = str(rule_name or "")
        upper = raw.upper()

        if any(k in raw or k in upper for k in ["握手", "SYN", "HANDSHAKE", "连接失败"]):
            return [
                "检查目标端口是否监听（netstat/ss）",
                "检查防火墙与ACL是否拦截SYN/SYN-ACK",
                "双向抓包确认三次握手中断位置",
            ]
        if any(k in raw or k in upper for k in ["重传", "RETRANS", "丢包"]):
            return [
                "检查链路丢包（ping/mtr）和网卡错误计数",
                "检查交换机/路由器队列是否出现丢弃",
            ]
        if any(k in raw or k in upper for k in ["重置", "RST", "拦截"]):
            return [
                "检查服务端应用日志与连接拒绝策略",
                "核查WAF/IPS/防火墙是否主动发送RST",
            ]
        if any(k in raw or k in upper for k in ["PMTU", "MTU", "分片", "长度异常", "FRAG"]):
            return [
                "做路径MTU探测并确认可达包长",
                "核查中间设备是否丢弃ICMP Fragmentation Needed",
                "必要时启用MSS钳制缓解大包黑洞",
            ]
        if "DNS" in upper:
            return [
                "使用dig/nslookup验证权威与递归解析链路",
                "核查上游DNS可达性与缓存命中情况",
            ]
        if "HTTP" in upper:
            return [
                "按状态码分布排查应用日志与上游依赖",
                "区分4xx（请求问题）与5xx（服务端问题）",
            ]
        if "TLS" in upper:
            return [
                "使用openssl s_client校验证书链与协议套件",
                "检查网关是否启用TLS卸载并改写握手参数",
            ]
        if any(k in raw or k in upper for k in ["延迟", "卡慢", "JITTER", "RTT"]):
            return [
                "结合RTT与服务处理耗时区分网络与应用瓶颈",
                "对照高峰与低峰时段做链路路径对比",
            ]
        if any(k in raw or k in upper for k in ["ZERO WINDOW", "WINDOW FULL", "零窗口", "窗口阻塞"]):
            return [
                "检查接收端CPU/内存/缓冲区资源",
                "优化socket缓冲参数并核查应用消费能力",
            ]
        if any(k in raw or k in upper for k in ["ICMP", "不可达", "TTL"]):
            return ["使用traceroute定位不可达跳点并核对路由/ACL"]
        if any(k in raw or k in upper for k in ["对称", "ASYMMETRY"]):
            return ["双向抓包确认回程路径与NAT策略一致性"]
        if any(k in raw or k in upper for k in ["广播", "组播", "BROADCAST"]):
            return ["检查二层环路、STP状态与IGMP Snooping配置"]
        return []

    @classmethod
    def _root_cause_to_dict(cls, rc: RootCause) -> Dict[str, Any]:
        confidence = float(getattr(rc, "confidence", 0.0) or 0.0)
        suggestions = list(getattr(rc, "suggestions", []) or getattr(rc, "recommended_actions", []) or [])
        name = str(getattr(rc, "name", "") or "")
        summary = str(getattr(rc, "summary", "") or "")
        evidence = cls._dedupe_strings([ev for ev in getattr(rc, "evidence", []) if ev], limit=10)
        tags = cls._extract_signal_tags(name, summary, " ".join(evidence[:4]))
        return {
            "name": name,
            "summary": summary,
            "confidence": confidence,
            "confidence_percent": f"{confidence * 100:.0f}%",
            "affected_scope": str(getattr(rc, "affected_scope", "") or ""),
            "evidence": evidence,
            "suggestions": cls._dedupe_strings([sg for sg in suggestions if sg], limit=8),
            "recommended_actions": cls._dedupe_strings([sg for sg in suggestions if sg], limit=8),
            "tags": tags,
            "tag_keys": ",".join(tags),
            "rc_id": hashlib.sha1(f"{name}|{summary}".encode("utf-8")).hexdigest()[:12],
        }

    @staticmethod
    def _extract_key_metrics(metrics: Dict[str, Any]) -> List[List[str]]:
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}
        app_protocol = metrics.get("application_protocol", {}) or {}

        items: List[List[str]] = []
        if tcp:
            items.append(["TCP 重传率", f"{float(tcp.get('retrans_rate', 0) or 0) * 100:.2f}%"])
            items.append(["TCP RST 率", f"{float(tcp.get('rst_rate', 0) or 0) * 100:.2f}%"])
            items.append(["最大 RTT", f"{float(tcp.get('max_rtt', 0) or 0) * 1000:.0f} ms"])
        if net:
            items.append(["流量不对称比", f"{float(net.get('asymmetry_ratio', 1) or 1):.1f}:1"])
            items.append(["广播/组播速率", f"{float(net.get('broadcast_rate', 0) or 0):.1f} pkt/s"])
        if app:
            items.append(["HTTP 错误响应数", str(int(app.get("http_error_responses", 0) or 0))])
            items.append(["DNS 错误响应数", str(int(app.get("dns_error_rcode", 0) or 0))])
            items.append(["TLS Alert 数", str(int(app.get("tls_alerts", 0) or 0))])
        if app_protocol:
            top_app = sorted(app_protocol.items(), key=lambda kv: kv[1], reverse=True)[:3]
            items.append(["Top 应用层协议", ", ".join([f"{k}:{v}" for k, v in top_app])])
        return items

    @staticmethod
    def _is_summary_rule_name(rule_name: str) -> bool:
        text = str(rule_name or "").strip()
        if not text or set(text) <= {"?"}:
            return True
        markers = ("智能关联结论", "关联结论", "综合结论", "总体结论", "汇总结论")
        return any(marker in text for marker in markers)

    @staticmethod
    def _score_over_threshold(value: float, threshold: float, base: float = 4.0, gain: float = 2.5, cap: float = 12.0) -> float:
        if threshold <= 0 or value <= threshold:
            return 0.0
        ratio = value / max(threshold, 1e-6)
        score = base + max(0.0, (ratio - 1.0) * gain)
        return min(score, cap)

    @staticmethod
    def _keyword_hits(text: str, keywords: List[str]) -> int:
        merged = str(text or "").upper()
        return sum(1 for kw in keywords if kw and str(kw).upper() in merged)

    @classmethod
    def _extract_signal_tags(cls, *texts: str) -> List[str]:
        merged = " ".join([str(t or "") for t in texts]).strip()
        if not merged:
            return ["mixed"]
        upper = merged.upper()
        tags: List[str] = []

        def mark(tag: str, keys: List[str]):
            if any(k in merged or k in upper for k in keys):
                tags.append(tag)

        mark("loss", ["重传", "丢包", "RETRANS", "DUP ACK", "FAST RETRANS"])
        mark("handshake", ["握手", "SYN", "连接失败", "SYN-ACK"])
        mark("reset", ["RST", "重置", "拒绝", "拦截"])
        mark("latency", ["RTT", "延迟", "抖动", "JITTER", "卡慢"])
        mark("dns", ["DNS", "NXDOMAIN", "SERVFAIL"])
        mark("http", ["HTTP", "5XX", "4XX", "请求失败"])
        mark("mtu", ["PMTU", "MTU", "分片", "FRAG", "LENGTH"])
        mark("interrupt", ["单向", "中断", "NO_RESPONSE", "UNREACHABLE", "回程"])
        mark("security", ["ACL", "防火墙", "WAF", "IPS", "策略"])
        mark("resource", ["ZERO WINDOW", "窗口", "BUFFER", "CPU", "MEMORY", "会话表", "CONNTRACK"])
        if not tags:
            tags.append(cls._issue_domain(merged))
        clean = []
        seen = set()
        for tag in tags:
            tag = str(tag or "").strip().lower()
            if not tag or tag == "none":
                continue
            if tag not in seen:
                seen.add(tag)
                clean.append(tag)
        return clean or ["mixed"]

    @staticmethod
    def _stable_tag_order(tags: List[str]) -> List[str]:
        priority = {
            "security": 1,
            "loss": 2,
            "handshake": 3,
            "reset": 4,
            "latency": 5,
            "dns": 6,
            "http": 7,
            "mtu": 8,
            "interrupt": 9,
            "resource": 10,
            "network": 11,
            "transport": 12,
            "application": 13,
            "mixed": 99,
        }
        deduped: List[str] = []
        seen = set()
        for tag in tags or []:
            t = str(tag or "").strip().lower()
            if not t or t in seen:
                continue
            seen.add(t)
            deduped.append(t)
        return sorted(deduped, key=lambda t: (priority.get(t, 50), t))

    def _infer_primary_issue(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        faults: List[Dict[str, Any]],
    ) -> Dict[str, str]:
        cfg = metrics.get("config_thresholds") or self._extract_thresholds()
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}

        retrans = float(tcp.get("retrans_rate", 0.0) or 0.0)
        rst = float(tcp.get("rst_rate", 0.0) or 0.0)
        max_rtt_ms = float(tcp.get("max_rtt", 0.0) or 0.0) * 1000.0
        asym_ratio = float(net.get("asymmetry_ratio", 1.0) or 1.0)
        frag_needed = int(net.get("icmp_frag_needed", 0) or 0)
        unreachable = int(net.get("icmp_unreachable", 0) or 0)

        retrans_th = float(cfg.get("retransmission_rate", 0.05))
        rst_th = float(cfg.get("rst_rate", 0.02))
        rtt_th = float(cfg.get("rtt_high_ms", cfg.get("rtt_threshold_ms", 500)))
        asym_th = float(cfg.get("asymmetry_ratio", 10.0))
        dns_th = float(cfg.get("dns_failure_rate", 0.05))
        http_th = float(cfg.get("http_error_rate", 0.1))

        dns_total = max(int(app.get("dns_total", 0) or 0), 1)
        dns_err = int(app.get("dns_error_rcode", 0) or 0)
        dns_rate = dns_err / dns_total

        http_total = max(int(app.get("http_total", 0) or 0), 1)
        http_err = int(app.get("http_error_responses", 0) or 0)
        http_rate = http_err / http_total

        anomaly_texts: List[str] = []
        for item in anomalies:
            rule_name = str(item.get("rule_name", "") or "").strip()
            if rule_name and not self._is_summary_rule_name(rule_name):
                anomaly_texts.append(rule_name)
            anomaly_texts.append(str(item.get("description", "") or ""))
            anomaly_texts.extend([str(ev) for ev in (item.get("evidence", []) or [])[:4] if str(ev).strip()])

        fault_texts = [
            f"{str(row.get('endpoint', '') or '')} {str(row.get('diagnosis', '') or '')}"
            for row in (faults or [])
        ]
        merged_text = " ".join([*anomaly_texts, *fault_texts]).upper()

        handshake_faults = sum(
            1
            for row in (faults or [])
            if any(k in str(row.get("diagnosis", "") or "") for k in ["握手", "SYN后无SYN-ACK", "SYN-ACK后无ACK", "连接失败"])
        )
        retrans_faults = sum(
            1
            for row in (faults or [])
            if any(k in str(row.get("diagnosis", "") or "") for k in ["重传", "丢包"])
        )
        reset_faults = sum(
            1
            for row in (faults or [])
            if any(k in str(row.get("diagnosis", "") or "") for k in ["RST", "重置", "拦截", "拒绝"])
        )
        one_way_faults = sum(
            1
            for row in (faults or [])
            if any(k in str(row.get("diagnosis", "") or "") for k in ["单向", "无响应", "中断", "回包路径异常"])
        )

        candidates: List[Dict[str, Any]] = []

        loss_score = self._score_over_threshold(retrans, retrans_th, base=4.5, gain=2.8, cap=13.0)
        loss_score += min(retrans_faults * 1.6, 5.0)
        loss_score += self._keyword_hits(merged_text, ["重传", "RETRANS", "丢包", "LOSS", "DUP ACK"]) * 1.2
        if loss_score > 0:
            candidates.append(
                {
                    "score": loss_score,
                    "label": "链路丢包/重传异常",
                    "evidence": f"TCP重传率 {retrans * 100:.2f}%（阈值 < {retrans_th * 100:.2f}%）",
                    "action_hint": "优先检查链路CRC/丢包、队列拥塞与ECMP哈希路径",
                }
            )

        handshake_score = min(handshake_faults * 3.2, 11.0)
        handshake_score += self._keyword_hits(
            merged_text,
            ["握手失败", "SYN后无SYN-ACK", "SYN-ACK后无ACK", "连接失败", "HANDSHAKE"],
        ) * 1.4
        if handshake_score > 0:
            candidates.append(
                {
                    "score": handshake_score,
                    "label": "TCP连接建立异常",
                    "evidence": f"握手异常流 {handshake_faults} 条，存在 SYN/SYN-ACK 链路断点",
                    "action_hint": "优先核查监听端口、SYN/SYN-ACK回程路径与ACL策略",
                }
            )

        policy_score = self._score_over_threshold(rst, rst_th, base=4.0, gain=2.6, cap=12.0)
        policy_score += min(reset_faults * 1.5, 4.5)
        policy_score += self._keyword_hits(merged_text, ["RST", "重置", "拦截", "ACL", "防火墙", "WAF", "IPS", "拒绝"]) * 1.1
        if policy_score > 0:
            candidates.append(
                {
                    "score": policy_score,
                    "label": "连接重置/策略拦截风险",
                    "evidence": f"TCP RST率 {rst * 100:.2f}%（阈值 < {rst_th * 100:.2f}%）",
                    "action_hint": "优先核查服务拒绝日志与安全设备策略命中记录",
                }
            )

        latency_score = self._score_over_threshold(max_rtt_ms, rtt_th, base=3.8, gain=2.2, cap=10.5)
        latency_score += self._keyword_hits(merged_text, ["延迟", "RTT", "JITTER", "抖动", "卡慢"]) * 1.2
        if latency_score > 0:
            candidates.append(
                {
                    "score": latency_score,
                    "label": "高延迟/抖动异常",
                    "evidence": f"RTT峰值 {max_rtt_ms:.0f}ms（阈值 < {rtt_th:.0f}ms）",
                    "action_hint": "优先排查拥塞跳点与高峰时段链路时延抖动",
                }
            )

        dns_score = self._score_over_threshold(dns_rate, dns_th, base=3.0, gain=2.0, cap=9.0)
        if dns_err > 0:
            dns_score += 2.5 + min(dns_err / 5.0, 3.0)
        dns_score += self._keyword_hits(merged_text, ["DNS", "SERVFAIL", "NXDOMAIN"]) * 1.1
        if dns_score > 0:
            candidates.append(
                {
                    "score": dns_score,
                    "label": "DNS解析异常",
                    "evidence": f"DNS失败 {dns_err}/{dns_total}（{dns_rate * 100:.2f}%）",
                    "action_hint": "优先核查本地DNS转发、上游递归链路与错误码分布",
                }
            )

        http_score = self._score_over_threshold(http_rate, http_th, base=3.0, gain=2.0, cap=9.0)
        if http_err > 0:
            http_score += 2.2 + min(http_err / 10.0, 3.0)
        http_score += self._keyword_hits(merged_text, ["HTTP", "5XX", "4XX", "REQUEST FAILED"]) * 1.0
        if http_score > 0:
            candidates.append(
                {
                    "score": http_score,
                    "label": "HTTP请求失败/响应异常",
                    "evidence": f"HTTP错误 {http_err}/{http_total}（{http_rate * 100:.2f}%）",
                    "action_hint": "优先按状态码和上游依赖定位应用处理链路故障",
                }
            )

        interrupt_score = self._score_over_threshold(asym_ratio, asym_th, base=3.2, gain=2.0, cap=9.5)
        interrupt_score += min(one_way_faults * 2.0, 5.0)
        interrupt_score += self._keyword_hits(merged_text, ["单向", "NO_RESPONSE", "中断", "UNREACHABLE", "回包路径异常"]) * 1.2
        if unreachable > 0:
            interrupt_score += 2.0
        if interrupt_score > 0:
            candidates.append(
                {
                    "score": interrupt_score,
                    "label": "网络中断/回程路径异常",
                    "evidence": f"流量不对称比 {asym_ratio:.1f}:1（阈值 <= {asym_th:.1f}:1）",
                    "action_hint": "优先检查回程路由、NAT一致性与链路收敛事件",
                }
            )

        pmtu_score = 0.0
        if frag_needed > 0:
            pmtu_score += 4.0 + min(frag_needed / 4.0, 4.0)
        pmtu_score += self._keyword_hits(merged_text, ["PMTU", "MTU", "分片", "FRAG", "FRAGMENTATION NEEDED"]) * 1.3
        if pmtu_score > 0:
            candidates.append(
                {
                    "score": pmtu_score,
                    "label": "PMTU/分片异常",
                    "evidence": f"ICMP Fragmentation Needed 报文 {frag_needed} 个",
                    "action_hint": "优先验证PMTUD回包策略与MSS钳制设置",
                }
            )

        if candidates:
            best = sorted(candidates, key=lambda item: float(item.get("score", 0.0) or 0.0), reverse=True)[0]
            return {
                "label": str(best.get("label", "") or "待进一步确认"),
                "evidence": str(best.get("evidence", "") or ""),
                "action_hint": str(best.get("action_hint", "") or ""),
            }

        for item in anomalies:
            rule_name = str(item.get("rule_name", "") or "").strip()
            if rule_name and not self._is_summary_rule_name(rule_name):
                return {
                    "label": self._extract_issue_label(rule_name) or rule_name,
                    "evidence": "由规则引擎识别到主异常类型",
                    "action_hint": "优先围绕主异常做端到端复核",
                }
        if faults:
            diagnosis = str(faults[0].get("diagnosis", "传输异常") or "传输异常")
            return {
                "label": self._extract_issue_label(diagnosis) or diagnosis,
                "evidence": str(faults[0].get("endpoint", "") or ""),
                "action_hint": "优先从最高影响故障流开始分层排查",
            }
        return {"label": "未发现明显异常", "evidence": "", "action_hint": "保持趋势监控并保留本次基线"}

    def _pick_top_issue(self, metrics: Dict[str, Any], anomalies: List[Dict[str, Any]], faults: List[Dict[str, Any]]) -> str:
        primary = self._infer_primary_issue(metrics, anomalies, faults)
        label = str(primary.get("label", "") or "").strip()
        evidence = str(primary.get("evidence", "") or "").strip()
        if not label or label == "未发现明显异常":
            return "未发现明显异常"
        if len(evidence) > 60:
            evidence = evidence[:59] + "…"
        return f"{label}" + (f"（{evidence}）" if evidence else "")

    @classmethod
    def _extract_issue_label(cls, text: str) -> str:
        raw = str(text or "").strip()
        if not raw:
            return ""
        upper = raw.upper()

        mappings: List[Tuple[List[str], str]] = [
            (["握手失败", "SYN后无SYN-ACK", "SYN无响应"], "握手失败（SYN后无SYN-ACK）"),
            (["SYN-ACK后无ACK", "握手未完成"], "握手未完成（SYN-ACK后无ACK）"),
            (["重置", "RST"], "连接重置（RST）"),
            (["重传", "RETRANS"], "数据传输异常（重传）"),
            (["ZERO WINDOW", "零窗口"], "接收端窗口阻塞（ZeroWindow）"),
            (["单向", "NO_RESPONSE"], "单向流量（回包路径异常）"),
            (["PMTU", "MTU", "分片"], "路径MTU/分片异常"),
            (["长度异常"], "数据包长度异常"),
            (["DNS"], "DNS解析异常"),
            (["HTTP"], "应用层响应异常"),
            (["TLS"], "TLS握手异常"),
            (["延迟", "卡慢", "RTT", "JITTER"], "高延迟/抖动异常"),
        ]
        for keys, label in mappings:
            if any(k in raw or k in upper for k in keys):
                return label

        cleaned = re.split(r"[。；;，,]", raw)[0].strip()
        if len(cleaned) > 28:
            cleaned = cleaned[:27] + "…"
        return cleaned

    def _build_prioritized_actions(
        self,
        metrics: Dict[str, Any],
        root_causes: List[Dict[str, Any]],
        anomalies: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        action_pool: Dict[str, Dict[str, Any]] = {}

        def push(action: str, score: float, source: str):
            text = str(action or "").strip()
            if not text:
                return
            key = self._normalize_text(text)
            current = action_pool.get(key)
            if current is None or score > float(current.get("score", 0.0) or 0.0):
                action_pool[key] = {"action": text, "source": source, "score": score}

        for rc in root_causes:
            base = float(rc.get("confidence", 0.0) or 0.0) * 100
            for idx, sg in enumerate(rc.get("suggestions", []) or rc.get("recommended_actions", [])):
                push(str(sg), base - idx * 2, f"根因:{rc.get('name', '未知')}")

        sev_weight = {"CRITICAL": 35.0, "HIGH": 25.0, "MEDIUM": 15.0, "LOW": 8.0}
        for an in anomalies:
            base = sev_weight.get(str(an.get("severity_name", "LOW")).upper(), 8.0)
            for idx, sg in enumerate(an.get("suggestions", [])):
                push(str(sg), base - idx, f"异常:{an.get('rule_name', '未知')}")

        tcp = metrics.get("tcp", {}) or {}
        app = metrics.get("application", {}) or {}
        net = metrics.get("network", {}) or {}
        retrans_rate = float(tcp.get("retrans_rate", 0) or 0)
        rst_rate = float(tcp.get("rst_rate", 0) or 0)
        dns_err = int(app.get("dns_error_rcode", 0) or 0)
        http_err = int(app.get("http_error_responses", 0) or 0)
        frag_needed = int(net.get("icmp_frag_needed", 0) or 0)
        if retrans_rate >= 0.03:
            push("检查链路丢包、队列拥塞和QoS策略", 22, "TCP重传率")
        if rst_rate >= 0.01:
            push("排查服务端端口状态与安全策略拦截", 20, "TCP RST率")
        if dns_err > 0:
            push("核查本地DNS与上游递归链路可达性", 18, "DNS错误响应")
        if http_err > 0:
            push("按状态码定位应用侧错误与上游依赖故障", 16, "HTTP错误响应")
        if frag_needed > 0:
            push("核查PMTUD回包策略并验证MSS钳制配置", 17, "ICMP Fragmentation Needed")

        if not action_pool:
            push("持续观察关键指标，确认网络波动是否复现", 10, "默认建议")
            push("对热点IP执行连通性与时延基线检查", 9, "默认建议")

        ranked = sorted(action_pool.values(), key=lambda item: float(item.get("score", 0.0) or 0.0), reverse=True)
        return [{"action": item["action"], "source": item["source"]} for item in ranked[:12]]

    @classmethod
    def _dedupe_prioritized_actions(cls, actions: List[Dict[str, str]]) -> List[Dict[str, str]]:
        deduped: List[Dict[str, str]] = []
        seen = set()
        for item in actions:
            action = str(item.get("action", "")).strip()
            if not action:
                continue
            key = cls._normalize_text(action)
            if key in seen:
                continue
            seen.add(key)
            deduped.append({"action": action, "source": str(item.get("source", "未知来源"))})
        return deduped

    @staticmethod
    def _flow_score(flow: Dict[str, Any]) -> float:
        syn = int(flow.get("syn_count", 0) or 0)
        syn_ack = int(flow.get("syn_ack_count", 0) or 0)
        final_ack = int(flow.get("final_ack_count", 0) or 0)
        rst = int(flow.get("rst_count", 0) or 0)
        retrans = int(flow.get("retrans_count", 0) or 0)
        dup_ack = int(flow.get("dup_ack_count", 0) or 0)
        zero_window = int(flow.get("zero_window_count", 0) or 0)
        out_of_order = int(flow.get("out_of_order_count", 0) or 0)
        packet_count = int(flow.get("packet_count", 0) or 0)
        max_gap = float(flow.get("max_gap", 0.0) or 0.0)
        score = (
            rst * 7
            + retrans * 4
            + dup_ack * 2
            + zero_window * 4
            + out_of_order * 2
            + len(flow.get("issues", []) or []) * 6
            + min(packet_count / 20.0, 20)
            + min(max_gap * 2, 20)
        )
        if syn > 0 and syn_ack == 0:
            score += 45
        if syn_ack > 0 and final_ack == 0:
            score += 35
        return round(score, 2)

    @classmethod
    def _flow_diagnosis(cls, flow: Dict[str, Any]) -> str:
        syn = int(flow.get("syn_count", 0) or 0)
        syn_ack = int(flow.get("syn_ack_count", 0) or 0)
        final_ack = int(flow.get("final_ack_count", 0) or 0)
        rst = int(flow.get("rst_count", 0) or 0)
        retrans = int(flow.get("retrans_count", 0) or 0)
        zero_window = int(flow.get("zero_window_count", 0) or 0)
        max_gap = float(flow.get("max_gap", 0.0) or 0.0)
        a_to_b = int(flow.get("packets_a_to_b", 0) or 0)
        b_to_a = int(flow.get("packets_b_to_a", 0) or 0)

        if syn > 0 and syn_ack == 0:
            return "握手失败（SYN后无SYN-ACK）"
        if syn_ack > 0 and final_ack == 0:
            return "握手未完成（SYN-ACK后无ACK）"
        if rst > 0 and retrans > 0:
            return "连接被重置并伴随重传"
        if rst > 0:
            return "连接重置（RST）"
        if zero_window > 0:
            return "接收端窗口阻塞（ZeroWindow）"
        if retrans > 0:
            return "数据传输异常（重传）"
        if a_to_b > 3 and b_to_a == 0:
            return "单向流量（回包路径异常）"
        if max_gap > 3.0:
            return "间歇卡顿（包间隔过大）"

        issues = flow.get("issues", []) or []
        if issues:
            return cls._extract_issue_label(str(issues[0])) or str(issues[0])
        return "异常流量"

    def _build_fault_locations(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        limit: int = 6,
    ) -> List[Dict[str, Any]]:
        flows = metrics.get("problem_flows", []) or []
        ranked = sorted(flows, key=self._flow_score, reverse=True)[: max(limit, 1)]
        rows: List[Dict[str, Any]] = []
        for idx, flow in enumerate(ranked, 1):
            score = self._flow_score(flow)
            diagnosis = self._flow_diagnosis(flow)
            packet_count = int(flow.get("packet_count", 0) or 0)
            if score >= 50 or any(k in diagnosis for k in ["握手失败", "握手未完成", "连接被重置", "单向流量"]):
                impact = "高"
            elif score >= 20 or packet_count >= 30:
                impact = "中"
            else:
                impact = "低"
            rows.append(
                {
                    "rank": idx,
                    "endpoint": (
                        f"{flow.get('src_ip', 'unknown')}:{int(flow.get('src_port', 0) or 0)} -> "
                        f"{flow.get('dst_ip', 'unknown')}:{int(flow.get('dst_port', 0) or 0)}"
                    ),
                    "diagnosis": diagnosis,
                    "impact": impact,
                    "evidence": (
                        f"SYN={int(flow.get('syn_count', 0) or 0)}, "
                        f"SYN-ACK={int(flow.get('syn_ack_count', 0) or 0)}, "
                        f"ACK={int(flow.get('ack_count', 0) or 0)}, "
                        f"RST={int(flow.get('rst_count', 0) or 0)}, "
                        f"重传={int(flow.get('retrans_count', 0) or 0)}, "
                        f"最大间隔={float(flow.get('max_gap', 0.0) or 0.0):.2f}s"
                    ),
                    "tags": self._extract_signal_tags(diagnosis),
                    "tag_keys": ",".join(self._extract_signal_tags(diagnosis)),
                    "_score": score,
                    "_packets": packet_count,
                }
            )

        if not rows and anomalies:
            for idx, item in enumerate(anomalies[: max(limit, 1)], 1):
                rows.append(
                    {
                        "rank": idx,
                        "endpoint": "抓包范围内（未提取到明确流端点）",
                        "diagnosis": str(item.get("rule_name", "异常")),
                        "impact": "中",
                        "evidence": str(item.get("description", "")),
                        "tags": self._extract_signal_tags(
                            str(item.get("rule_name", "")),
                            str(item.get("description", "")),
                        ),
                        "tag_keys": ",".join(
                            self._extract_signal_tags(
                                str(item.get("rule_name", "")),
                                str(item.get("description", "")),
                            )
                        ),
                        "_score": float(item.get("count", 0) or 0),
                        "_packets": int(item.get("count", 0) or 0),
                    }
                )

        ranked_rows = sorted(rows, key=lambda x: (float(x.get("_score", 0)), int(x.get("_packets", 0))), reverse=True)
        for idx, row in enumerate(ranked_rows[: max(limit, 1)], 1):
            row["rank"] = idx
            row.pop("_score", None)
            row.pop("_packets", None)
        return ranked_rows[: max(limit, 1)]

    def _build_flow_interactions(
        self,
        metrics: Dict[str, Any],
        limit: int = 12,
        output_level: int = 3,
    ) -> List[Dict[str, Any]]:
        flows = metrics.get("problem_flows", []) or []
        ranked = sorted(flows, key=self._flow_score, reverse=True)[: max(limit, 1)]
        interactions: List[Dict[str, Any]] = []
        for flow in ranked:
            src = f"{flow.get('src_ip', 'unknown')}:{int(flow.get('src_port', 0) or 0)}"
            dst = f"{flow.get('dst_ip', 'unknown')}:{int(flow.get('dst_port', 0) or 0)}"
            a_to_b = int(flow.get("packets_a_to_b", 0) or 0)
            b_to_a = int(flow.get("packets_b_to_a", 0) or 0)
            ratio = b_to_a / max(a_to_b, 1)
            syn = int(flow.get("syn_count", 0) or 0)
            syn_ack = int(flow.get("syn_ack_count", 0) or 0)
            final_ack = int(flow.get("final_ack_count", 0) or 0)
            rst = int(flow.get("rst_count", 0) or 0)
            ratio_note = ""
            if syn > 0 and syn_ack == 0:
                handshake = "失败：SYN后无SYN-ACK"
                ratio_note = "握手未建立，回包比仅含握手阶段（不代表业务回包率）"
            elif rst > 0 and final_ack == 0:
                handshake = "失败：连接被RST重置"
                ratio_note = "连接被重置，回包比仅含故障前阶段（不代表业务回包率）"
            elif syn_ack > 0 and final_ack == 0:
                handshake = "异常：SYN-ACK后无ACK"
                ratio_note = "握手未完成，回包比仅含握手阶段（不代表业务回包率）"
            elif syn > 0 and syn_ack > 0 and final_ack > 0:
                handshake = "完成"
            else:
                handshake = "非握手阶段流"

            retrans = int(flow.get("retrans_count", 0) or 0)
            zero_window = int(flow.get("zero_window_count", 0) or 0)
            if rst > 0:
                transfer = f"重置中断（RST={rst}）"
            elif zero_window > 0:
                transfer = f"接收阻塞（ZeroWindow={zero_window}）"
            elif retrans > 0:
                transfer = f"重传偏高（重传={retrans}）"
            else:
                transfer = "未发现明显传输异常"

            issues = "；".join((flow.get("issues", []) or [])[:5]) or "无"
            if output_level <= 3:
                issues = "；".join((flow.get("issues", []) or [])[:3]) or "无"
            ratio_text = f"{ratio:.2f}"
            if ratio_note:
                ratio_text = f"{ratio:.2f}（{ratio_note}）"

            interactions.append(
                {
                    "endpoint": f"{src} -> {dst}",
                    "handshake": handshake,
                    "transfer": transfer,
                    "direction": f"{a_to_b}/{b_to_a}",
                    "response_ratio": ratio_text,
                    "issues": issues,
                    "key_breakpoint": self._flow_diagnosis(flow),
                    "score": self._flow_score(flow),
                    "max_gap": f"{float(flow.get('max_gap', 0.0) or 0.0):.2f}s",
                    "tags": self._extract_signal_tags(handshake, transfer, issues),
                    "tag_keys": ",".join(self._extract_signal_tags(handshake, transfer, issues)),
                }
            )

        return sorted(
            interactions,
            key=lambda item: (float(item.get("score", 0.0) or 0.0), float(str(item.get("max_gap", "0s")).replace("s", ""))),
            reverse=True,
        )[: max(limit, 1)]

    @staticmethod
    def _impact_profile(score: float) -> Dict[str, str]:
        val = float(score or 0.0)
        if val >= 60:
            return {"label": "高", "stars": "★★★", "pct": "100", "class": "impact-high"}
        if val >= 30:
            return {"label": "中", "stars": "★★", "pct": "70", "class": "impact-mid"}
        return {"label": "低", "stars": "★", "pct": "40", "class": "impact-low"}

    @staticmethod
    def _diagnosis_badge(diagnosis: str) -> Dict[str, str]:
        text = str(diagnosis or "")
        upper = text.upper()
        if any(k in text for k in ["握手失败", "握手未完成"]) or "SYN" in upper:
            return {"label": "握手失败", "class": "tag-handshake", "icon": "●"}
        if any(k in text for k in ["重置", "RST"]) or "RST" in upper:
            return {"label": "连接重置", "class": "tag-reset", "icon": "●"}
        if any(k in text for k in ["重传", "丢包"]) or "RETRANS" in upper:
            return {"label": "高重传", "class": "tag-retrans", "icon": "●"}
        if "ZERO WINDOW" in upper or "窗口" in text:
            return {"label": "窗口阻塞", "class": "tag-window", "icon": "●"}
        if any(k in text for k in ["DNS", "HTTP", "TLS"]):
            return {"label": "应用异常", "class": "tag-app", "icon": "●"}
        return {"label": "数据异常", "class": "tag-generic", "icon": "●"}

    def _build_fault_flow_details(self, metrics: Dict[str, Any], limit: int = 12) -> List[Dict[str, Any]]:
        flows = metrics.get("problem_flows", []) or []
        ranked = sorted(flows, key=self._flow_score, reverse=True)[: max(limit, 1)]
        rows: List[Dict[str, Any]] = []
        for idx, flow in enumerate(ranked, 1):
            diagnosis = self._flow_diagnosis(flow)
            badge = self._diagnosis_badge(diagnosis)
            score = self._flow_score(flow)
            impact = self._impact_profile(score)
            src_ip = flow.get("src_ip", "unknown")
            dst_ip = flow.get("dst_ip", "unknown")
            src_port = int(flow.get("src_port", 0) or 0)
            dst_port = int(flow.get("dst_port", 0) or 0)
            endpoint = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            a_to_b = int(flow.get("packets_a_to_b", 0) or 0)
            b_to_a = int(flow.get("packets_b_to_a", 0) or 0)
            packet_count = max(int(flow.get("packet_count", 0) or 0), 1)
            retrans = int(flow.get("retrans_count", 0) or 0)
            retrans_rate = retrans / max(packet_count, 1)
            rtt_max_ms = float(flow.get("rtt_max_ms", 0.0) or 0.0)
            if rtt_max_ms <= 0:
                synack_ms = float(flow.get("handshake_synack_ms", 0.0) or 0.0)
                ack_ms = float(flow.get("handshake_ack_ms", 0.0) or 0.0)
                rtt_max_ms = max(synack_ms, ack_ms, 0.0)
            max_gap = float(flow.get("max_gap", 0.0) or 0.0)
            syn = int(flow.get("syn_count", 0) or 0)
            syn_ack = int(flow.get("syn_ack_count", 0) or 0)
            final_ack = int(flow.get("final_ack_count", 0) or 0)
            if syn > 0 and syn_ack == 0:
                handshake = "SYN -> 无SYN-ACK"
            elif syn_ack > 0 and final_ack == 0:
                handshake = "SYN-ACK -> 无ACK"
            elif syn > 0 and syn_ack > 0 and final_ack > 0:
                handshake = "握手完成"
            else:
                handshake = "非典型握手流"

            if int(flow.get("rst_count", 0) or 0) > 0:
                transfer = "连接中断（RST）"
            elif int(flow.get("zero_window_count", 0) or 0) > 0:
                transfer = "接收端阻塞（ZeroWindow）"
            elif retrans > 0:
                transfer = "数据重传异常"
            elif max_gap > 3.0:
                transfer = "链路间歇卡顿"
            else:
                transfer = "传输阶段需进一步复核"

            packet_scope = (
                f"#{int(flow.get('first_packet_no', 0) or 0)}-#{int(flow.get('last_packet_no', 0) or 0)}"
                if int(flow.get("first_packet_no", 0) or 0) > 0 and int(flow.get("last_packet_no", 0) or 0) > 0
                else f"总包数 {packet_count}"
            )
            trace_filter = (
                f"ip.addr=={src_ip} && ip.addr=={dst_ip} && "
                f"(tcp.port=={src_port} || tcp.port=={dst_port})"
            )
            key_fields = ", ".join(
                [
                    "tcp.flags",
                    "tcp.analysis.retransmission",
                    "tcp.analysis.ack_rtt",
                    "tcp.window_size",
                ]
            )
            tags = self._extract_signal_tags(diagnosis, handshake, transfer)
            rows.append(
                {
                    "rank": idx,
                    "endpoint": endpoint,
                    "diagnosis": diagnosis,
                    "badge_label": badge["label"],
                    "badge_icon": badge["icon"],
                    "badge_class": badge["class"],
                    "impact_label": impact["label"],
                    "impact_stars": impact["stars"],
                    "impact_pct": impact["pct"],
                    "impact_class": impact["class"],
                    "handshake": handshake,
                    "transfer": transfer,
                    "direction": f"{a_to_b}/{b_to_a}",
                    "response_ratio": f"{(b_to_a / max(a_to_b, 1)):.2f}",
                    "evidence_compact": (
                        f"重传 {retrans}/{packet_count} ({retrans_rate * 100:.1f}%), "
                        f"RTT峰值 {rtt_max_ms:.0f}ms, 最大间隔 {max_gap:.2f}s"
                    ),
                    "packet_scope": packet_scope,
                    "evidence_id": str(flow.get("evidence_id", "") or ""),
                    "trace_filter": trace_filter,
                    "key_fields": key_fields,
                    "tags": tags,
                    "tag_keys": ",".join(tags),
                }
            )
        return rows

    def _build_incident_snapshot(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
        management_summary: Dict[str, Any],
        primary_issue: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        cfg = metrics.get("config_thresholds") or self._extract_thresholds()
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}

        retrans_th = float(cfg.get("retransmission_rate", 0.05))
        asym_ratio = float(net.get("asymmetry_ratio", 1.0) or 1.0)
        asym_th = float(cfg.get("asymmetry_ratio", 10.0))

        primary = primary_issue or self._infer_primary_issue(metrics, anomalies, fault_locations)
        issue_label = str(primary.get("label", "") or "").strip()
        issue_evidence = str(primary.get("evidence", "") or "").strip()
        if issue_label and issue_label != "未发现明显异常":
            conclusion = f"检测到主要问题：{issue_label}" + (f"（{issue_evidence}）" if issue_evidence else "")
        else:
            retrans = float(tcp.get("retrans_rate", 0.0) or 0.0)
            if retrans > retrans_th:
                conclusion = f"检测到传输质量退化：TCP 重传率 {retrans * 100:.2f}%（阈值 < {retrans_th * 100:.2f}%）"
            else:
                conclusion = "未发现稳定复现的单一故障主因，建议按决策树继续分层定位"

        if fault_locations:
            top = fault_locations[0]
            impact = f"主要影响点：{top.get('endpoint', '未知端点')}（{top.get('diagnosis', '待确认')}）"
        else:
            impact = f"影响范围：{management_summary.get('impact_scope', '待进一步确认')}"

        if asym_ratio > asym_th:
            impact += f"，且流量不对称比达到 {asym_ratio:.1f}:1"

        top_actions = management_summary.get("top_actions", []) or []
        emergency = str(top_actions[0]).strip() if top_actions else str(primary.get("action_hint", "")).strip()
        if not emergency:
            emergency = "先执行端到端连通性与双向抓包定位断点"
        action_hint = str(primary.get("action_hint", "") or "").strip()
        if action_hint and action_hint not in emergency:
            emergency = f"{emergency}；补充：{action_hint}"
        if int(app.get("dns_error_rcode", 0) or 0) > 0:
            emergency += "；并同步核查 DNS 解析链路"
        return {
            "conclusion": conclusion,
            "impact": impact,
            "emergency_action": emergency,
        }

    def _build_key_metric_rows(self, metrics: Dict[str, Any]) -> List[Dict[str, str]]:
        cfg = metrics.get("config_thresholds") or self._extract_thresholds()
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}

        def row(metric: str, current: str, threshold: str, exceeded: bool) -> Dict[str, str]:
            return {
                "metric": metric,
                "current": current,
                "threshold": threshold,
                "status": "超阈值" if exceeded else "正常",
                "status_class": "status-bad" if exceeded else "status-good",
            }

        retrans = float(tcp.get("retrans_rate", 0.0) or 0.0)
        rst = float(tcp.get("rst_rate", 0.0) or 0.0)
        max_rtt_ms = float(tcp.get("max_rtt", 0.0) or 0.0) * 1000.0
        asym = float(net.get("asymmetry_ratio", 1.0) or 1.0)
        broad = float(net.get("broadcast_rate", 0.0) or 0.0)

        retrans_th = float(cfg.get("retransmission_rate", 0.05))
        rst_th = float(cfg.get("rst_rate", 0.02))
        rtt_th = float(cfg.get("rtt_high_ms", cfg.get("rtt_threshold_ms", 500)))
        asym_th = float(cfg.get("asymmetry_ratio", 10))
        broad_th = float(cfg.get("broadcast_rate", 1000))

        http_total = max(int(app.get("http_total", 0) or 0), 1)
        dns_total = max(int(app.get("dns_total", 0) or 0), 1)
        http_err_rate = float(app.get("http_error_responses", 0) or 0) / http_total
        dns_err_rate = float(app.get("dns_error_rcode", 0) or 0) / dns_total
        http_th = float(cfg.get("http_error_rate", 0.1))
        dns_th = float(cfg.get("dns_failure_rate", 0.05))

        rows = [
            row("TCP 重传率", f"{retrans * 100:.2f}%", f"< {retrans_th * 100:.2f}%", retrans > retrans_th),
            row("TCP RST 率", f"{rst * 100:.2f}%", f"< {rst_th * 100:.2f}%", rst > rst_th),
            row("最大 RTT", f"{max_rtt_ms:.0f}ms", f"< {rtt_th:.0f}ms", max_rtt_ms > rtt_th),
            row("流量不对称比", f"{asym:.1f}:1", f"<= {asym_th:.1f}:1", asym > asym_th),
            row("广播/组播速率", f"{broad:.1f} pkt/s", f"< {broad_th:.1f} pkt/s", broad > broad_th),
            row("HTTP 错误率", f"{http_err_rate * 100:.2f}%", f"< {http_th * 100:.2f}%", http_err_rate > http_th),
            row("DNS 失败率", f"{dns_err_rate * 100:.2f}%", f"< {dns_th * 100:.2f}%", dns_err_rate > dns_th),
        ]
        return rows

    def _build_timeline_insights(self, metrics: Dict[str, Any], limit: int = 6) -> List[Dict[str, str]]:
        timeline = metrics.get("traffic_timeline", {}) or {}
        series = timeline.get("series", []) or []
        if not series:
            return []
        cfg = metrics.get("config_thresholds") or self._extract_thresholds()
        retrans_th = float(cfg.get("retransmission_rate", 0.05))
        rst_th = float(cfg.get("rst_rate", 0.02))
        rtt_th = float(cfg.get("rtt_high_ms", cfg.get("rtt_threshold_ms", 500)))
        window_s = float(timeline.get("window_seconds", 10.0) or 10.0)

        ranked = sorted(
            series,
            key=lambda row: (
                float(row.get("retrans_rate", 0.0) or 0.0) * 100
                + float(row.get("rst_rate", 0.0) or 0.0) * 120
                + float(row.get("avg_rtt_ms", 0.0) or 0.0) / 100.0
                + float(row.get("packets_per_sec", 0.0) or 0.0) / 20.0
            ),
            reverse=True,
        )[: max(limit, 1)]

        rows: List[Dict[str, str]] = []
        for point in ranked:
            idx = int(point.get("index", 0) or 0)
            start_s = float(point.get("time_s", 0.0) or 0.0)
            end_s = start_s + window_s
            retrans_rate = float(point.get("retrans_rate", 0.0) or 0.0)
            avg_rtt = float(point.get("avg_rtt_ms", 0.0) or 0.0)
            if retrans_rate > retrans_th * 1.8 or avg_rtt > rtt_th * 1.5:
                severity = "高"
            elif retrans_rate > retrans_th or avg_rtt > rtt_th:
                severity = "中"
            else:
                severity = "低"
            tags: List[str] = []
            if retrans_rate > retrans_th:
                tags.append("loss")
            if float(point.get("rst_rate", 0.0) or 0.0) > rst_th:
                tags.append("reset")
            if avg_rtt > rtt_th:
                tags.append("latency")
            if int(point.get("dns_packets", 0) or 0) > 0:
                tags.append("dns")
            if int(point.get("http_packets", 0) or 0) > 0:
                tags.append("http")
            if not tags:
                tags.append("mixed")
            trace_filter = f"frame.time_relative >= {start_s:.3f} && frame.time_relative < {end_s:.3f}"
            rows.append(
                {
                    "window": f"#{idx}",
                    "window_index": str(idx),
                    "range": f"{start_s:.1f}s ~ {end_s:.1f}s",
                    "window_start": f"{start_s:.3f}",
                    "window_end": f"{end_s:.3f}",
                    "packets_per_sec": f"{float(point.get('packets_per_sec', 0.0) or 0.0):.2f}",
                    "throughput_mbps": f"{float(point.get('throughput_mbps', 0.0) or 0.0):.3f}",
                    "retrans_rate": f"{retrans_rate * 100:.2f}%",
                    "rst_rate": f"{float(point.get('rst_rate', 0.0) or 0.0) * 100:.2f}%",
                    "avg_rtt_ms": f"{avg_rtt:.0f}",
                    "severity": severity,
                    "tags": tags,
                    "tag_keys": ",".join(tags),
                    "trace_filter": trace_filter,
                }
            )
        return rows

    def _build_decision_tree(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        _ = fault_locations
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        cfg = metrics.get("config_thresholds") or self._extract_thresholds()
        retrans = float(tcp.get("retrans_rate", 0.0) or 0.0)
        retrans_th = float(cfg.get("retransmission_rate", 0.05))
        rst = float(tcp.get("rst_rate", 0.0) or 0.0)
        rst_th = float(cfg.get("rst_rate", 0.02))
        frag_needed = int(net.get("icmp_frag_needed", 0) or 0)
        anomaly_text = " ".join([f"{a.get('rule_name', '')} {a.get('description', '')}" for a in anomalies]).upper()

        rows: List[Dict[str, str]] = [
            {
                "step": "1",
                "question": "端口连通性是否稳定（tcping/nc）？",
                "if_yes": "进入第2步（质量判断）",
                "if_no": "优先检查监听、ACL、防火墙策略",
                "reason": "先确认连通性，再区分链路质量或应用瓶颈",
                "tags": ["handshake", "security"],
                "tag_keys": "handshake,security",
            },
            {
                "step": "2",
                "question": f"TCP重传率是否 > {retrans_th * 100:.2f}%（当前 {retrans * 100:.2f}%）？",
                "if_yes": "执行丢包/抖动链路排查（mtr、接口错误计数）",
                "if_no": "进入第3步（策略与应用）",
                "reason": "高重传通常优先指向链路质量或拥塞",
                "tags": ["loss", "latency"],
                "tag_keys": "loss,latency",
            },
            {
                "step": "3",
                "question": f"RST率是否 > {rst_th * 100:.2f}%（当前 {rst * 100:.2f}%）？",
                "if_yes": "排查服务拒绝、安全策略、会话上限",
                "if_no": "进入第4步（路径与MTU）",
                "reason": "RST异常常见于策略重置或服务端主动拒绝",
                "tags": ["reset", "security"],
                "tag_keys": "reset,security",
            },
        ]
        rows.append(
            {
                "step": "4",
                "question": f"是否存在 PMTU/分片信号（ICMP frag-needed={frag_needed}）？",
                "if_yes": "执行 MTU 探测与 MSS 钳制核验",
                "if_no": "进入第5步（应用层时延）",
                "reason": "路径 MTU 异常会导致大包黑洞和反复重传",
                "tags": ["mtu", "interrupt"],
                "tag_keys": "mtu,interrupt",
            }
        )
        app_hint = "DNS/HTTP/TLS" if any(k in anomaly_text for k in ["DNS", "HTTP", "TLS"]) else "业务处理链路"
        rows.append(
            {
                "step": "5",
                "question": f"{app_hint} 是否出现错误率或时延峰值？",
                "if_yes": "进入应用日志与上游依赖排查",
                "if_no": "回看抓包时序并补充双向抓包证据",
                "reason": "网络层无明显超阈值时应转向应用与依赖链路",
                "tags": ["dns", "http", "latency"],
                "tag_keys": "dns,http,latency",
            }
        )
        return rows

    def _build_mtu_impact_samples(self, metrics: Dict[str, Any], limit: int = 5) -> List[Dict[str, str]]:
        network = metrics.get("network", {}) or {}
        flows = metrics.get("problem_flows", []) or []
        rows: List[Dict[str, str]] = []
        for flow in flows:
            frag_issues = flow.get("frag_issues", []) or []
            len_issues = flow.get("length_anomalies", []) or []
            if not frag_issues and not len_issues:
                continue
            endpoint = (
                f"{flow.get('src_ip', 'unknown')}:{int(flow.get('src_port', 0) or 0)} -> "
                f"{flow.get('dst_ip', 'unknown')}:{int(flow.get('dst_port', 0) or 0)}"
            )
            packet_scope = (
                f"#{int(flow.get('first_packet_no', 0) or 0)}-#{int(flow.get('last_packet_no', 0) or 0)}"
                if int(flow.get("first_packet_no", 0) or 0) > 0 and int(flow.get("last_packet_no", 0) or 0) > 0
                else f"总包数 {int(flow.get('packet_count', 0) or 0)}"
            )
            issue_text = str((frag_issues + len_issues)[0])
            rows.append(
                {
                    "endpoint": endpoint,
                    "packet_scope": packet_scope,
                    "symptom": "分片/长度异常",
                    "evidence": issue_text,
                }
            )
            if len(rows) >= max(limit, 1):
                break

        if int(network.get("icmp_frag_needed", 0) or 0) > 0 and len(rows) < max(limit, 1):
            rows.append(
                {
                    "endpoint": "全局网络层",
                    "packet_scope": "ICMP type=3 code=4",
                    "symptom": "Path MTU 反馈",
                    "evidence": f"检测到 ICMP Fragmentation Needed: {int(network.get('icmp_frag_needed', 0) or 0)}",
                }
            )
        return rows

    def _build_chart_fallback_summary(self, metrics: Dict[str, Any]) -> List[str]:
        timeline = metrics.get("traffic_timeline", {}) or {}
        series = timeline.get("series", []) or []
        if not series:
            return []
        peak_retrans = max(series, key=lambda row: float(row.get("retrans_rate", 0.0) or 0.0))
        peak_rtt = max(series, key=lambda row: float(row.get("avg_rtt_ms", 0.0) or 0.0))
        peak_pps = max(series, key=lambda row: float(row.get("packets_per_sec", 0.0) or 0.0))
        return [
            (
                "重传峰值窗口: #{idx} (t={time:.1f}s), retrans={rate:.2f}%".format(
                    idx=int(peak_retrans.get("index", 0) or 0),
                    time=float(peak_retrans.get("time_s", 0.0) or 0.0),
                    rate=float(peak_retrans.get("retrans_rate", 0.0) or 0.0) * 100,
                )
            ),
            (
                "RTT峰值窗口: #{idx} (t={time:.1f}s), avg_rtt={rtt:.0f}ms".format(
                    idx=int(peak_rtt.get("index", 0) or 0),
                    time=float(peak_rtt.get("time_s", 0.0) or 0.0),
                    rtt=float(peak_rtt.get("avg_rtt_ms", 0.0) or 0.0),
                )
            ),
            (
                "流量峰值窗口: #{idx} (t={time:.1f}s), pps={pps:.2f}, mbps={mbps:.3f}".format(
                    idx=int(peak_pps.get("index", 0) or 0),
                    time=float(peak_pps.get("time_s", 0.0) or 0.0),
                    pps=float(peak_pps.get("packets_per_sec", 0.0) or 0.0),
                    mbps=float(peak_pps.get("throughput_mbps", 0.0) or 0.0),
                )
            ),
        ]

    def _build_quick_action_card(
        self,
        incident_snapshot: Dict[str, str],
        management_summary: Dict[str, Any],
        command_checklist: List[Dict[str, str]],
        regression_checks: List[Dict[str, str]],
        key_metric_rows: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        conclusion = str(incident_snapshot.get("conclusion", "") or "待补充结论")
        impact = str(incident_snapshot.get("impact", "") or "影响范围待确认")

        # ── 智能选取快速行动步骤（1~3 步） ──
        # 从已按 priority+signal_score 排序的 command_checklist 中，
        # 按信号类别去重选取 top 步骤，每个信号类别最多 1 步，共 1~3 步。
        steps: List[str] = []
        if command_checklist:
            seen_signals: set = set()
            for item in command_checklist:
                signal = str(item.get("signal", "") or "mixed")
                if signal in seen_signals:
                    continue
                seen_signals.add(signal)
                purpose = str(item.get("purpose", "") or "执行排查动作").strip()
                steps.append(f"步骤{len(steps) + 1}：{purpose}")
                if len(steps) >= 3:
                    break
        if not steps:
            top_actions = management_summary.get("top_actions", []) or []
            if top_actions:
                for idx, action in enumerate(top_actions[:3], 1):
                    steps.append(f"步骤{idx}：{str(action).strip()}")
            else:
                steps.append("步骤1：先执行端到端连通性与双向抓包复核")

        success_criteria: List[str] = []
        for row in key_metric_rows:
            if str(row.get("status", "")) == "超阈值":
                success_criteria.append(f"{row.get('metric', '关键指标')} 回落至 {row.get('threshold', '阈值')} 以内")
            if len(success_criteria) >= 3:
                break
        if not success_criteria:
            for item in regression_checks[:3]:
                success_criteria.append(f"{item.get('check', '回归检查')} 达到 {item.get('target', '目标值')}")
        if not success_criteria:
            success_criteria = ["关键异常不再复现，核心业务探活稳定通过"]

        risk_level = str(management_summary.get("risk_level", "低") or "低")
        risk_class = str(management_summary.get("risk_class", "risk-low") or "risk-low")
        return {
            "conclusion": conclusion,
            "impact": impact,
            "steps": steps,
            "success_criteria": success_criteria,
            "risk_level": risk_level,
            "risk_class": risk_class,
        }

    @classmethod
    def _trace_filter_for_text(cls, text: str) -> str:
        merged = str(text or "").upper()
        if any(k in merged for k in ["RETRANS", "重传", "LOSS", "DUP ACK"]):
            return "tcp.analysis.retransmission || tcp.analysis.fast_retransmission"
        if any(k in merged for k in ["RST", "重置", "拒绝", "拦截"]):
            return "tcp.flags.reset==1"
        if any(k in merged for k in ["SYN", "握手", "连接失败"]):
            return "tcp.flags.syn==1 || tcp.flags.ack==1"
        if "DNS" in merged:
            return "dns && dns.flags.response==1 && dns.flags.rcode>0"
        if "HTTP" in merged:
            return "http.response.code >= 400"
        if any(k in merged for k in ["PMTU", "MTU", "分片", "FRAG"]):
            return "icmp.type==3 && icmp.code==4"
        if any(k in merged for k in ["RTT", "延迟", "抖动", "JITTER"]):
            return "tcp.analysis.ack_rtt"
        if any(k in merged for k in ["ICMP", "UNREACHABLE", "不可达"]):
            return "icmp.type==3"
        return "ip"

    def _build_evidence_traces(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_flow_details: List[Dict[str, Any]],
        timeline_insights: List[Dict[str, Any]],
        limit: int = 12,
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        problem_flows = metrics.get("problem_flows", []) or []

        for idx, row in enumerate(fault_flow_details[: max(limit, 1)], 1):
            entry_id = str(row.get("evidence_id", "") or "").strip() or f"FLOW-{idx:02d}"
            tags = row.get("tags", []) or self._extract_signal_tags(str(row.get("diagnosis", "")))
            rows.append(
                {
                    "trace_id": entry_id,
                    "source": "故障流",
                    "title": str(row.get("endpoint", "") or "未知端点"),
                    "packet_scope": str(row.get("packet_scope", "") or "抓包范围内"),
                    "display_filter": str(row.get("trace_filter", "") or ""),
                    "key_fields": str(row.get("key_fields", "") or "frame.number,ip.src,ip.dst"),
                    "hint": str(row.get("evidence_compact", "") or str(row.get("diagnosis", ""))),
                    "tags": tags,
                    "tag_keys": ",".join(tags),
                }
            )

        for idx, item in enumerate(anomalies[: max(limit, 1)], 1):
            rule_name = str(item.get("rule_name", "") or "")
            description = str(item.get("description", "") or "")
            threshold_rows = item.get("threshold_rows", []) or []
            threshold_summary = "；".join(
                [f"{x.get('metric', '')}:{x.get('actual', '')}->{x.get('threshold', '')}" for x in threshold_rows[:3]]
            )
            tags = item.get("tags", []) or self._extract_signal_tags(rule_name, description)
            rows.append(
                {
                    "trace_id": f"ANO-{idx:02d}",
                    "source": "异常规则",
                    "title": rule_name or f"异常#{idx}",
                    "packet_scope": "抓包全局",
                    "display_filter": self._trace_filter_for_text(f"{rule_name} {description}"),
                    "key_fields": "frame.number,frame.time_relative,ip.src,ip.dst,tcp.flags",
                    "hint": threshold_summary or (item.get("evidence", [""])[0] if item.get("evidence") else description),
                    "tags": tags,
                    "tag_keys": ",".join(tags),
                }
            )

        for row in timeline_insights[: max(limit // 2, 1)]:
            tags = row.get("tags", []) or ["mixed"]
            rows.append(
                {
                    "trace_id": f"WIN-{str(row.get('window_index', row.get('window', '0'))).replace('#', '')}",
                    "source": "时间窗",
                    "title": f"异常窗口 {row.get('window', '')}",
                    "packet_scope": str(row.get("range", "") or ""),
                    "display_filter": str(row.get("trace_filter", "") or ""),
                    "key_fields": "frame.time_relative,tcp.analysis.retransmission,tcp.analysis.ack_rtt",
                    "hint": (
                        f"重传{row.get('retrans_rate', '0%')} / RST{row.get('rst_rate', '0%')} / "
                        f"RTT{row.get('avg_rtt_ms', '0')}ms"
                    ),
                    "tags": tags,
                    "tag_keys": ",".join(tags),
                }
            )

        deduped: List[Dict[str, Any]] = []
        seen = set()
        for row in rows:
            key = self._normalize_text(
                f"{row.get('source', '')}|{row.get('title', '')}|{row.get('display_filter', '')}|{row.get('packet_scope', '')}"
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(row)
            if len(deduped) >= max(limit, 1):
                break

        # Try to enrich flow trace entries with explicit stream-level clues when available.
        if problem_flows:
            flow_map = {
                self._normalize_text(
                    f"{f.get('src_ip', '')}:{int(f.get('src_port', 0) or 0)}->{f.get('dst_ip', '')}:{int(f.get('dst_port', 0) or 0)}"
                ): f
                for f in problem_flows
            }
            for row in deduped:
                if str(row.get("source", "")) != "故障流":
                    continue
                title_key = self._normalize_text(str(row.get("title", "")).replace(" ", ""))
                flow = flow_map.get(title_key)
                if not flow:
                    continue
                row["display_filter"] = (
                    f"ip.addr=={flow.get('src_ip', '')} && ip.addr=={flow.get('dst_ip', '')} && "
                    f"(tcp.port=={int(flow.get('src_port', 0) or 0)} || tcp.port=={int(flow.get('dst_port', 0) or 0)})"
                )
        return deduped

    def _build_anomaly_groups(
        self,
        anomalies: List[Dict[str, Any]],
        root_causes: List[Dict[str, Any]],
        fault_flow_details: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        domain_map: Dict[str, Dict[str, Any]] = {}
        for an in anomalies:
            domain = str(an.get("domain", "") or self._domain_label(f"{an.get('rule_name', '')} {an.get('description', '')}"))
            if domain not in domain_map:
                domain_map[domain] = {
                    "group_id": f"DOM-{hashlib.sha1(domain.encode('utf-8')).hexdigest()[:8]}",
                    "name": domain,
                    "count": 0,
                    "high_risk_count": 0,
                    "evidence_count": 0,
                    "top_rules": [],
                    "tags": [],
                    "tag_keys": "",
                    "default_expanded": False,
                }
            group = domain_map[domain]
            group["count"] += 1
            if str(an.get("severity_name", "")).upper() in {"CRITICAL", "HIGH"}:
                group["high_risk_count"] += 1
            group["evidence_count"] += len(an.get("evidence", []) or [])
            rule_name = str(an.get("rule_name", "") or "").strip()
            if rule_name and rule_name not in group["top_rules"] and len(group["top_rules"]) < 4:
                group["top_rules"].append(rule_name)
            for tag in an.get("tags", []) or []:
                if tag and tag not in group["tags"]:
                    group["tags"].append(tag)

        by_domain = sorted(
            domain_map.values(),
            key=lambda row: (int(row.get("high_risk_count", 0)), int(row.get("count", 0))),
            reverse=True,
        )
        for row in by_domain:
            row["default_expanded"] = int(row.get("high_risk_count", 0)) > 0
            row["tag_keys"] = ",".join(row.get("tags", []) or [])

        by_root: List[Dict[str, Any]] = []
        anomaly_tags = [(set(a.get("tags", []) or []), a) for a in anomalies]
        for rc in root_causes[:8]:
            rc_tag_list = self._dedupe_strings([str(t or "").strip().lower() for t in (rc.get("tags", []) or []) if str(t or "").strip()], limit=0)
            rc_tag_set = set(rc_tag_list)
            matched = []
            for tags, an in anomaly_tags:
                if rc_tag_set and tags.intersection(rc_tag_set):
                    matched.append(an)
                    continue
                if not rc_tag_set and self._normalize_text(rc.get("name", "")) in self._normalize_text(an.get("rule_name", "")):
                    matched.append(an)
            ordered_rc_tags = self._stable_tag_order(rc_tag_list)
            by_root.append(
                {
                    "group_id": f"RC-{str(rc.get('rc_id', '')) or hashlib.sha1(str(rc.get('name', '')).encode('utf-8')).hexdigest()[:8]}",
                    "name": str(rc.get("name", "") or "待确认根因"),
                    "confidence": str(rc.get("confidence_percent", "") or "--"),
                    "count": len(matched),
                    "high_risk_count": sum(
                        1 for m in matched if str(m.get("severity_name", "")).upper() in {"CRITICAL", "HIGH"}
                    ),
                    "summary": str(rc.get("summary", "") or ""),
                    "tags": ordered_rc_tags or ["mixed"],
                    "tag_keys": ",".join(ordered_rc_tags or ["mixed"]),
                    "default_expanded": True if float(rc.get("confidence", 0.0) or 0.0) >= 0.7 else False,
                }
            )

        if not by_root and fault_flow_details:
            by_root.append(
                {
                    "group_id": "RC-AUTO",
                    "name": "按故障流自动聚合",
                    "confidence": "--",
                    "count": len(fault_flow_details),
                    "high_risk_count": sum(1 for f in fault_flow_details if str(f.get("impact_label", "")) == "高"),
                    "summary": "暂无稳定根因，按故障流高影响项聚合展示。",
                    "tags": ["mixed"],
                    "tag_keys": "mixed",
                    "default_expanded": True,
                }
            )

        return {
            "by_domain": by_domain,
            "by_root_cause": by_root,
        }

    def _build_confidence_explainer(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        root_causes: List[Dict[str, Any]],
        report_profile: Dict[str, Any],
        primary_issue: Dict[str, str],
    ) -> Dict[str, Any]:
        rule_hits = len(anomalies)
        threshold_breaches = sum(
            1 for an in anomalies for row in (an.get("threshold_rows", []) or []) if str(row.get("status", "")) == "超阈值"
        )
        evidence_count = sum(len(an.get("evidence", []) or []) for an in anomalies)
        top_root_conf = max([float(rc.get("confidence", 0.0) or 0.0) for rc in root_causes], default=0.0)

        conflicts: List[str] = []
        dominant_domain = str(report_profile.get("dominant_domain", "综合") or "综合")
        primary_tags = set(self._extract_signal_tags(primary_issue.get("label", ""), primary_issue.get("evidence", "")))
        if root_causes:
            top_rc = root_causes[0]
            rc_tags = set(top_rc.get("tags", []) or [])
            if rc_tags and primary_tags and not primary_tags.intersection(rc_tags):
                conflicts.append("主问题标签与最高置信根因标签不完全重合，存在交叉异常影响。")
        if dominant_domain == "综合" and rule_hits >= 4:
            conflicts.append("异常跨多个域分布，单一根因解释能力受限。")
        if rule_hits > 0 and threshold_breaches == 0:
            conflicts.append("规则命中较多但硬阈值超限较少，需补充上下文证据确认。")

        score = 0.25
        score += min(rule_hits, 12) / 12.0 * 0.22
        score += min(threshold_breaches, 12) / 12.0 * 0.20
        score += min(evidence_count, 24) / 24.0 * 0.18
        score += top_root_conf * 0.28
        score -= min(len(conflicts), 4) * 0.08

        # Sample density as a confidence floor/ceiling adjuster.
        basic = metrics.get("basic", {}) or {}
        total_packets = int(basic.get("total_packets", 0) or 0)
        if total_packets < 300:
            score -= 0.05
        elif total_packets > 50000:
            score += 0.03
        score = max(0.05, min(score, 0.99))

        if score >= 0.75:
            level = "高"
            level_class = "status-good"
        elif score >= 0.55:
            level = "中"
            level_class = "status-good"
        else:
            level = "低"
            level_class = "status-bad"

        signals = [
            {
                "label": "规则命中",
                "value": str(rule_hits),
                "detail": "触发异常规则数量",
            },
            {
                "label": "超阈值证据",
                "value": str(threshold_breaches),
                "detail": "阈值对比中明确超限项",
            },
            {
                "label": "有效证据条目",
                "value": str(evidence_count),
                "detail": "异常与根因中的证据总量",
            },
            {
                "label": "最高根因置信",
                "value": f"{top_root_conf * 100:.0f}%",
                "detail": "根因候选的最高置信度",
            },
        ]

        summary = (
            f"当前结论可信度 {score * 100:.0f}%（{level}），由规则命中、阈值超限与证据完整度共同决定。"
        )
        return {
            "score": score,
            "score_percent": f"{score * 100:.0f}%",
            "level": level,
            "level_class": level_class,
            "signals": signals,
            "conflicts": conflicts,
            "summary": summary,
        }

    def _build_blind_spots(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        root_causes: List[Dict[str, Any]],
        scope_ratio: float,
    ) -> List[Dict[str, str]]:
        basic = metrics.get("basic", {}) or {}
        tcp = metrics.get("tcp", {}) or {}
        app = metrics.get("application", {}) or {}
        timeline = metrics.get("traffic_timeline", {}) or {}
        problem_flows = metrics.get("problem_flows", []) or []
        rows: List[Dict[str, str]] = []

        total_packets = int(basic.get("total_packets", 0) or 0)
        if total_packets < 300:
            rows.append(
                {
                    "level": "中",
                    "title": "样本规模偏小",
                    "detail": f"当前仅 {total_packets} 包，统计稳定性有限。",
                    "suggestion": "建议补抓至少 3~5 分钟业务高峰样本后再复核。",
                }
            )

        if float(scope_ratio or 0.0) < 0.25:
            rows.append(
                {
                    "level": "中",
                    "title": "过滤范围较窄",
                    "detail": f"过滤命中率仅 {float(scope_ratio or 0.0) * 100:.2f}%，可能遗漏关键对话。",
                    "suggestion": "建议追加全流量或放宽过滤条件后再做对比。",
                }
            )

        if len(problem_flows) <= 0 and anomalies:
            rows.append(
                {
                    "level": "高",
                    "title": "缺少端点级故障流",
                    "detail": "已识别规则异常，但未提取到稳定的故障流端点。",
                    "suggestion": "建议同步采集双向抓包与设备日志，补齐会话级证据。",
                }
            )

        if not root_causes and anomalies:
            rows.append(
                {
                    "level": "中",
                    "title": "根因收敛不足",
                    "detail": "规则命中存在，但尚未形成高置信根因。",
                    "suggestion": "按命令清单补充策略日志、链路指标与应用日志关联。",
                }
            )

        rtt_samples = int(tcp.get("rtt_samples", 0) or 0)
        if rtt_samples <= 0 and int(tcp.get("total", 0) or 0) > 0:
            rows.append(
                {
                    "level": "低",
                    "title": "RTT样本不足",
                    "detail": "TCP 包存在，但 RTT 样本为空或不足。",
                    "suggestion": "建议保留 ACK RTT 字段并延长抓包窗口以提升时延分析可信度。",
                }
            )

        if len(timeline.get("series", []) or []) < 3 and total_packets > 0:
            rows.append(
                {
                    "level": "低",
                    "title": "时间轴粒度不足",
                    "detail": "时间窗口点数过少，不利于识别波峰与抖动节奏。",
                    "suggestion": "建议延长抓包时长或减小窗口宽度后复测。",
                }
            )

        dns_total = int(app.get("dns_total", 0) or 0)
        http_total = int(app.get("http_total", 0) or 0)
        if dns_total <= 0 and http_total <= 0:
            rows.append(
                {
                    "level": "低",
                    "title": "应用层样本有限",
                    "detail": "DNS/HTTP 样本不足，应用侧结论可能不完整。",
                    "suggestion": "建议同步抓取应用协议流量或补充业务日志。",
                }
            )

        level_order = {"高": 3, "中": 2, "低": 1}
        rows = sorted(rows, key=lambda x: level_order.get(str(x.get("level", "低")), 0), reverse=True)
        return rows

    def _build_report_diff(
        self,
        history_trend: Dict[str, Any],
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        records = history_trend.get("records", []) or []
        if not records:
            return {}

        previous = records[-1]
        tcp = metrics.get("tcp", {}) or {}
        current_anomalies = len(anomalies)
        current_packets = int(metrics.get("basic", {}).get("total_packets", 0) or 0)
        current_retrans = float(tcp.get("retrans_rate", 0.0) or 0.0)
        current_rst = float(tcp.get("rst_rate", 0.0) or 0.0)

        diff_rows: List[Dict[str, str]] = []

        def add(metric: str, prev_val: float, cur_val: float, fmt: str = "count"):
            delta = cur_val - prev_val
            if fmt == "pct":
                prev_text = f"{prev_val * 100:.2f}%"
                cur_text = f"{cur_val * 100:.2f}%"
                delta_text = f"{delta * 100:+.2f}%"
            else:
                prev_text = f"{int(prev_val)}"
                cur_text = f"{int(cur_val)}"
                delta_text = f"{int(delta):+d}"
            trend = "上升" if delta > 0 else ("下降" if delta < 0 else "持平")
            status_class = "status-bad" if delta > 0 else "status-good"
            diff_rows.append(
                {
                    "metric": metric,
                    "previous": prev_text,
                    "current": cur_text,
                    "delta": delta_text,
                    "trend": trend,
                    "status_class": status_class,
                }
            )

        add("异常数量", float(int(previous.get("anomalies", 0) or 0)), float(current_anomalies), "count")
        add("TCP重传率", float(previous.get("retrans_rate", 0.0) or 0.0), current_retrans, "pct")
        add("TCP RST率", float(previous.get("rst_rate", 0.0) or 0.0), current_rst, "pct")
        add("抓包总包数", float(int(previous.get("packets", 0) or 0)), float(current_packets), "count")

        worsen = sum(1 for row in diff_rows if str(row.get("trend", "")) == "上升")
        improve = sum(1 for row in diff_rows if str(row.get("trend", "")) == "下降")
        summary = "较上次总体改善" if improve > worsen else ("较上次有恶化迹象" if worsen > improve else "较上次基本持平")
        return {
            "baseline_timestamp": str(previous.get("timestamp", "") or history_trend.get("baseline_timestamp", "")),
            "summary": summary,
            "rows": diff_rows,
            "has_diff": True,
        }

    def _build_business_impact(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        basic = metrics.get("basic", {}) or {}
        flow_analysis = metrics.get("flow_analysis", {}) or {}
        tcp = metrics.get("tcp", {}) or {}
        app = metrics.get("application", {}) or {}
        problem_flows = metrics.get("problem_flows", []) or []

        total_flows = max(int(flow_analysis.get("total_flows", len(problem_flows)) or len(problem_flows) or 1), 1)
        problem_flow_count = len(problem_flows)
        impacted_flow_ratio = problem_flow_count / total_flows

        total_bytes = max(int(basic.get("total_bytes", 0) or 0), 1)
        impacted_bytes = sum(int(row.get("total_bytes", 0) or 0) for row in problem_flows)
        impacted_traffic_ratio = impacted_bytes / total_bytes

        tcp_failures = int(tcp.get("connection_failures", 0) or 0)
        http_errors = int(app.get("http_error_responses", 0) or 0)
        dns_errors = int(app.get("dns_error_rcode", 0) or 0)
        failed_signals = tcp_failures + http_errors + dns_errors

        if impacted_flow_ratio >= 0.35 or impacted_traffic_ratio >= 0.35:
            impact_level = "高"
            impact_class = "risk-high"
        elif impacted_flow_ratio >= 0.15 or impacted_traffic_ratio >= 0.15:
            impact_level = "中"
            impact_class = "risk-mid"
        else:
            impact_level = "低"
            impact_class = "risk-low"

        top_endpoint = str(fault_locations[0].get("endpoint", "")) if fault_locations else "待确认"
        headline = (
            f"问题流占比 {impacted_flow_ratio * 100:.2f}% ，影响流量占比 {impacted_traffic_ratio * 100:.2f}% ，"
            f"综合业务影响等级 {impact_level}。"
        )
        cards = [
            {
                "label": "问题流占比",
                "value": f"{problem_flow_count}/{total_flows} ({impacted_flow_ratio * 100:.2f}%)",
                "status": "偏高" if impacted_flow_ratio >= 0.15 else "可控",
            },
            {
                "label": "受影响流量",
                "value": f"{impacted_bytes:,}/{total_bytes:,} Bytes ({impacted_traffic_ratio * 100:.2f}%)",
                "status": "偏高" if impacted_traffic_ratio >= 0.15 else "可控",
            },
            {
                "label": "失败信号量",
                "value": str(failed_signals),
                "status": "偏高" if failed_signals > 0 else "正常",
            },
            {
                "label": "首要影响端点",
                "value": top_endpoint or "待确认",
                "status": "需优先排查" if top_endpoint else "待补充",
            },
        ]
        return {
            "headline": headline,
            "impact_level": impact_level,
            "impact_class": impact_class,
            "cards": cards,
            "anomaly_count": len(anomalies),
        }

    @staticmethod
    def _build_closure_score(
        regression_checks: List[Dict[str, str]],
        acceptance_checklist: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        rows = list(regression_checks or []) + list(acceptance_checklist or [])
        if not rows:
            return {
                "score": 0,
                "grade": "N/A",
                "status": "未评估",
                "status_class": "risk-mid",
                "pass_count": 0,
                "fail_count": 0,
                "pending_count": 0,
                "next_focus": [],
            }

        pass_count = 0
        fail_count = 0
        pending_count = 0
        next_focus: List[str] = []

        for row in rows:
            status = str(row.get("status", "") or "").strip()
            name = str(row.get("check", "") or row.get("item", "") or "检查项")
            if status == "通过":
                pass_count += 1
            elif status == "未通过":
                fail_count += 1
                if len(next_focus) < 4:
                    next_focus.append(name)
            else:
                pending_count += 1

        scored_total = max(pass_count + fail_count, 1)
        score = int(round((pass_count / scored_total) * 100))
        if fail_count > 0 and score >= 90:
            score = 89

        if score >= 85 and fail_count == 0:
            grade = "A"
            status = "闭环良好"
            status_class = "risk-low"
        elif score >= 60:
            grade = "B"
            status = "部分闭环"
            status_class = "risk-mid"
        else:
            grade = "C"
            status = "闭环风险高"
            status_class = "risk-high"

        return {
            "score": score,
            "grade": grade,
            "status": status,
            "status_class": status_class,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "pending_count": pending_count,
            "next_focus": next_focus,
        }

    def _build_attachments(
        self,
        file_path: str,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        root_causes: List[Dict[str, Any]],
        output_level: int,
    ) -> Dict[str, Any]:
        auto_items: List[Dict[str, str]] = []
        evidence_lines: List[str] = []
        for an in anomalies[:6]:
            rule = str(an.get("rule_name", "") or "")
            for ev in (an.get("evidence", []) or [])[:2]:
                text = str(ev or "").strip()
                if not text:
                    continue
                evidence_lines.append(f"{rule}: {text}" if rule else text)
                if len(evidence_lines) >= 6:
                    break
            if len(evidence_lines) >= 6:
                break

        if evidence_lines:
            auto_items.append(
                {
                    "type": "证据摘要",
                    "name": "关键证据片段",
                    "content": " | ".join(evidence_lines[:4]),
                }
            )

        log_path = Path(str(get_config().get("logging.file", "logs/analyzer.log") or "logs/analyzer.log"))
        if not log_path.is_absolute():
            log_path = Path.cwd() / log_path
        if log_path.exists() and log_path.is_file():
            try:
                size_kb = log_path.stat().st_size / 1024.0
            except Exception:
                size_kb = 0.0
            auto_items.append(
                {
                    "type": "日志文件",
                    "name": log_path.name,
                    "content": f"{log_path} ({size_kb:.1f} KB)",
                }
            )

        topo = metrics.get("ip_topology", {}) or {}
        if topo:
            node_count = len(topo.get("nodes", []) or [])
            edge_count = len(topo.get("edges", []) or [])
            auto_items.append(
                {
                    "type": "链路拓扑",
                    "name": "IP通信拓扑",
                    "content": f"节点 {node_count} / 边 {edge_count}（详见可视化图表）",
                }
            )

        if root_causes:
            auto_items.append(
                {
                    "type": "根因线索",
                    "name": str(root_causes[0].get("name", "根因候选") or "根因候选"),
                    "content": str(root_causes[0].get("summary", "") or "详见根因分析模块"),
                }
            )

        return {
            "auto_items": auto_items,
            "max_upload_hint": "建议单个附件不超过 2MB，避免报告过大",
            "sample_ref": Path(file_path).name,
            "enabled": output_level >= 3,
        }

    @staticmethod
    def _load_history_records() -> List[Dict[str, Any]]:
        cfg = get_config()
        history_file = Path(str(cfg.get("history.storage_file", "history.json") or "history.json"))
        if not history_file.is_absolute():
            history_file = Path.cwd() / history_file
        if not history_file.exists():
            return []
        for encoding in ("utf-8", "gbk"):
            try:
                content = json.loads(history_file.read_text(encoding=encoding))
                if isinstance(content, list):
                    return content
            except Exception:
                continue
        return []

    @staticmethod
    def _normalize_path_text(file_path: str) -> str:
        text = str(file_path or "").strip().replace("\\", "/").lower()
        return text

    def _build_history_trend(
        self,
        file_path: str,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        limit: int = 8,
    ) -> Dict[str, Any]:
        records = self._load_history_records()
        if not records:
            return {}

        target = self._normalize_path_text(file_path)
        target_stem = Path(file_path).stem.lower()

        matched: List[Dict[str, Any]] = []
        for item in records:
            record_path = self._normalize_path_text(item.get("file_path", ""))
            if not record_path:
                continue
            if record_path == target or Path(record_path).stem.lower() == target_stem:
                matched.append(item)
        if not matched:
            return {}

        matched = sorted(matched, key=lambda row: str(row.get("timestamp", "")))
        points: List[Dict[str, Any]] = []
        for row in matched[-limit:]:
            summary = row.get("summary", {}) or {}
            points.append(
                {
                    "timestamp": str(row.get("timestamp", "")),
                    "anomalies": int(summary.get("anomalies_count", 0) or 0),
                    "packets": int(summary.get("total_packets", 0) or 0),
                    "retrans_rate": float(summary.get("retrans_rate", 0.0) or 0.0),
                    "rst_rate": float(summary.get("rst_rate", 0.0) or 0.0),
                    "mode": str(summary.get("analysis_mode", "") or ""),
                }
            )

        current_anomalies = len(anomalies)
        current_packets = int(metrics.get("basic", {}).get("total_packets", 0) or 0)
        current_retrans = float(metrics.get("tcp", {}).get("retrans_rate", 0.0) or 0.0)
        current_rst = float(metrics.get("tcp", {}).get("rst_rate", 0.0) or 0.0)

        previous = points[-1] if points else None
        if previous:
            delta_anomalies = int(current_anomalies - int(previous.get("anomalies", 0) or 0))
            delta_packets = int(current_packets - int(previous.get("packets", 0) or 0))
            delta_retrans = float(current_retrans - float(previous.get("retrans_rate", 0.0) or 0.0))
            delta_rst = float(current_rst - float(previous.get("rst_rate", 0.0) or 0.0))
        else:
            delta_anomalies = 0
            delta_packets = 0
            delta_retrans = 0.0
            delta_rst = 0.0

        if delta_anomalies < 0 and delta_retrans <= 0 and delta_rst <= 0:
            trend_label = "改善"
        elif delta_anomalies > 0 or delta_retrans > 0 or delta_rst > 0:
            trend_label = "恶化"
        else:
            trend_label = "基本持平"

        return {
            "records": points,
            "history_count": len(matched),
            "baseline_timestamp": str(previous.get("timestamp", "") if previous else ""),
            "delta_anomalies": delta_anomalies,
            "delta_packets": delta_packets,
            "delta_retrans_pct": delta_retrans * 100.0,
            "delta_rst_pct": delta_rst * 100.0,
            "trend_label": trend_label,
            "current_anomalies": current_anomalies,
            "current_packets": current_packets,
        }

    def _build_command_checklist(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
        prioritized_actions: Optional[List[Dict[str, str]]] = None,
        output_level: int = 3,
    ) -> List[Dict[str, str]]:
        endpoint = fault_locations[0]["endpoint"] if fault_locations else "<src_ip>:<src_port> -> <dst_ip>:<dst_port>"
        dst = "目标IP"
        port = "目标端口"
        if "->" in endpoint:
            right = endpoint.split("->", 1)[1].strip()
            if ":" in right:
                dst, port = right.rsplit(":", 1)
        merged_text = (
            " ".join([f"{a.get('rule_name', '')} {a.get('description', '')}" for a in anomalies])
            + " "
            + str(fault_locations[0].get("diagnosis", "") if fault_locations else "")
        ).upper()
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}

        def _kw_hits(keys: List[str]) -> int:
            return sum(1 for k in keys if k in merged_text)

        scores: Dict[str, float] = {
            "handshake": 0.0,
            "loss": 0.0,
            "reset": 0.0,
            "window": 0.0,
            "pmtu": 0.0,
            "icmp": 0.0,
            "arp": 0.0,
            "dns": 0.0,
            "http": 0.0,
            "tls": 0.0,
        }
        scores["handshake"] += _kw_hits(["握手", "SYN", "连接失败", "半开"]) * 1.6
        scores["loss"] += _kw_hits(["重传", "丢包", "JITTER", "抖动", "卡慢", "延迟", "DUP ACK"]) * 1.4
        scores["reset"] += _kw_hits(["RST", "重置", "拦截", "拒绝"]) * 1.5
        scores["window"] += _kw_hits(["ZERO WINDOW", "WINDOW FULL", "零窗口", "窗口"]) * 1.3
        scores["pmtu"] += _kw_hits(["PMTU", "MTU", "分片", "长度异常", "FRAG"]) * 1.4
        scores["icmp"] += _kw_hits(["ICMP", "UNREACHABLE", "TTL", "不可达"]) * 1.2
        scores["arp"] += _kw_hits(["ARP", "欺骗", "广播风暴", "MAC 冲突", "MAC冲突"]) * 1.2
        scores["dns"] += _kw_hits(["DNS"]) * 1.3
        scores["http"] += _kw_hits(["HTTP"]) * 1.2
        scores["tls"] += _kw_hits(["TLS"]) * 1.2

        retrans_rate = float(tcp.get("retrans_rate", 0.0) or 0.0)
        rst_rate = float(tcp.get("rst_rate", 0.0) or 0.0)
        if retrans_rate > 0:
            scores["loss"] += min(retrans_rate / 0.05, 4.0)
        if rst_rate > 0:
            scores["reset"] += min(rst_rate / 0.02, 4.0)
            scores["handshake"] += min(rst_rate / 0.02, 2.0)
        if int(tcp.get("connection_failures", 0) or 0) > 0:
            scores["handshake"] += 2.0
        if int(tcp.get("zero_window", 0) or 0) > 0 or int(tcp.get("window_full", 0) or 0) > 0:
            scores["window"] += 2.0
        if int(net.get("icmp_frag_needed", 0) or 0) > 0:
            scores["pmtu"] += 3.0
            scores["icmp"] += 1.5
        if int(net.get("icmp_unreachable", 0) or 0) > 0 or int(net.get("icmp_ttl_expired", 0) or 0) > 0:
            scores["icmp"] += 2.0
        if int(net.get("arp_ip_mac_conflicts", 0) or 0) > 0:
            scores["arp"] += 2.0
        if int(app.get("dns_error_rcode", 0) or 0) > 0:
            scores["dns"] += 2.5
        if int(app.get("http_error_responses", 0) or 0) > 0:
            scores["http"] += 2.2
        if int(app.get("tls_alerts", 0) or 0) > 0:
            scores["tls"] += 2.0

        selected: List[Dict[str, Any]] = []
        seen = set()

        def add_item(
            purpose: str,
            command: str,
            expect: str,
            priority: int,
            sample: str = "",
            signal: str = "",
            why: str = "",
        ):
            key = self._normalize_text(f"{purpose}|{command}")
            if key in seen:
                return
            seen.add(key)
            signal_score = float(scores.get(signal, 0.0) or 0.0) if signal else 0.0
            selected.append(
                {
                    "purpose": purpose,
                    "command": command,
                    "expect": expect,
                    "sample": sample,
                    "why": why,
                    "signal": signal or "mixed",
                    "priority": int(priority + min(signal_score * 2.0, 14.0)),
                }
            )

        add_item(
            "确认故障端点可达与端口状态",
            f"[Windows] tcping {dst} {port} -n 20\n"
            f"[Windows] Test-NetConnection -ComputerName {dst} -Port {port} -InformationLevel Detailed\n"
            f"[Linux]   nc -vz -w 3 {dst} {port}\n"
            f"[Linux]   timeout 3 bash -c 'cat < /dev/null > /dev/tcp/{dst}/{port}'",
            "端口可达且连接耗时稳定",
            100,
            "正常: 20/20 成功，时延稳定；异常: 超时/拒绝/波动显著。",
            signal="handshake",
            why="这是所有网络故障的第一跳证据，可快速确认是否是连通性或端口层问题。",
        )
        add_item(
            "双向抓包复核故障断点",
            f"tshark -r <pcap> -Y \"ip.addr=={dst} && tcp.port=={port}\" "
            "-T fields -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport "
            "-e ip.dst -e tcp.dstport -e tcp.flags -e tcp.analysis.retransmission",
            "两端抓包时间线一致，可定位握手或传输中断位置",
            96,
            "正常: 双向时序完整；异常: 握手断点、单向流、重传峰值集中。",
            signal="loss",
            why="用于直接关联证据包和断点位置，是后续根因判断的核心依据。",
        )

        if scores["handshake"] > 0:
            add_item(
                "核对服务器监听与进程状态",
                f"[Windows] netstat -ano | findstr :{port}\n[Linux]   ss -lntp | grep {port}",
                "服务进程处于监听且与业务端口一致",
                94,
                "正常: LISTEN 且进程匹配；异常: 无监听或被其它进程占用。",
                signal="handshake",
                why="握手异常时先确认服务是否真实可用，可快速区分网络问题与服务侧问题。",
            )
            add_item(
                "确认连接跟踪与会话表容量（仅Linux）",
                "conntrack -S\nconntrack -L | wc -l",
                "会话表余量充足，无 table full 日志",
                88,
                "正常: insert_failed/drop 接近0；异常: table full 或 drop 持续增长。",
                signal="handshake",
                why="会话表耗尽会导致新连接建立失败，是常见的瞬时故障根因。",
            )

        if scores["loss"] > 0:
            add_item(
                "定位链路抖动与丢包跳点",
                f"[Windows] tracert {dst}\n"
                f"[Windows] ping {dst} -n 100\n"
                f"[Linux]   mtr -rwzc 100 {dst}",
                "无明显高丢包或异常高延迟跳点",
                93,
                "正常: 丢包≈0%，抖动低；异常: 某跳延迟/丢包明显升高。",
                signal="loss",
                why="重传/延迟异常通常来自链路质量问题，该命令可定位故障跳点。",
            )
            add_item(
                "核查网卡/接口丢包与错误计数",
                "[Windows] netstat -e  或  Get-NetAdapterStatistics\n[Linux]   ethtool -S <iface>  或  cat /proc/net/dev",
                "无持续增长的 drop/error/discard 计数",
                87,
                "正常: error/drop 计数平稳；异常: CRC/error/drop 快速增长。",
                signal="loss",
                why="接口错误计数可直接证明是否存在物理层或驱动层丢包。",
            )

        if scores["reset"] > 0:
            add_item(
                "核验防火墙/安全策略是否误拦截",
                "检查ACL/防火墙策略日志（命中源/目的IP与端口）",
                "无拒绝、重置或异常限速策略命中",
                92,
                "正常: 无 deny/reset 命中；异常: 命中同源/目的IP端口规则。",
                signal="reset",
                why="RST/拒绝相关异常常由策略触发，先看策略命中能最快闭环。",
            )

        if scores["pmtu"] > 0:
            add_item(
                "验证路径MTU可达上限",
                f"[Windows] ping {dst} -f -l 1472 -n 6\n"
                f"[Linux]   ping -M do -s 1472 -c 6 {dst}  # 逐步减小直到稳定",
                "找到不分片稳定包长，确认路径MTU",
                91,
                "正常: 大包可稳定回显；异常: 需要明显降低包长才可达。",
                signal="pmtu",
                why="分片/PMTU异常可直接通过大包探测复现，便于快速判定是否为黑洞问题。",
            )

        if scores["window"] > 0:
            add_item(
                "检查接收端资源与socket缓冲",
                "[Windows] Get-Process | Sort-Object CPU -Descending | Select-Object -First 10\n"
                "[Linux]   top -bn1 && free -h && sysctl net.ipv4.tcp_rmem",
                "接收端无资源瓶颈，缓冲参数匹配业务流量",
                85,
                "正常: 资源余量充足；异常: CPU/内存紧张或缓冲配置过小。",
                signal="window",
                why="窗口阻塞本质是接收端消费能力不足，需先看主机资源与缓冲参数。",
            )

        if scores["icmp"] > 0:
            add_item(
                "核实路由可达与回程路径一致性",
                "ip route get <dst> / traceroute -n <dst>（双向执行）",
                "正反向路径可达且无异常跳变",
                82,
                "正常: 正反向路径稳定；异常: 回程偏移、黑洞或不可达。",
                signal="icmp",
                why="ICMP不可达/TTL异常通常对应路由或回程问题，需要双向路径证据。",
            )
        if scores["arp"] > 0:
            add_item(
                "排查ARP风暴或ARP欺骗",
                "[Windows] arp -a  |  Get-NetNeighbor -AddressFamily IPv4\n"
                "[Linux]   ip neigh show  &&  arp -an",
                "同一IP不应频繁映射多个MAC，ARP表项变化应稳定",
                83,
                "正常: IP-MAC 映射稳定；异常: 同IP多MAC或频繁抖动。",
                signal="arp",
                why="ARP冲突会造成随机中断或单向通信，是二层高频隐患。",
            )
        if scores["dns"] > 0:
            add_item(
                "验证DNS解析链路与错误码",
                "dig <domain> +trace\nnslookup <domain>",
                "解析链路正常，无异常rcode",
                81,
                "正常: NOERROR 为主；异常: SERVFAIL/NXDOMAIN 异常峰值。",
                signal="dns",
                why="当DNS错误存在时，业务失败常是上游解析链路导致，需先排除DNS侧问题。",
            )
        if scores["http"] > 0:
            add_item(
                "确认应用错误集中点（URI/上游依赖）",
                "按状态码聚合 access.log（2xx/3xx/4xx/5xx）并关联 upstream 响应时间",
                "可区分网络侧异常与应用侧异常",
                79,
                "正常: 2xx/3xx 占比高；异常: 4xx/5xx 或上游耗时集中升高。",
                signal="http",
                why="HTTP状态码和上游耗时可以快速分离‘网络故障’与‘应用故障’。",
            )
        if scores["tls"] > 0:
            add_item(
                "校验TLS证书与协议兼容性",
                f"openssl s_client -connect {dst}:{port} -servername <SNI>",
                "证书链完整，握手协议与套件匹配",
                79,
                "正常: Verify return code: 0；异常: 证书链/协议不兼容。",
                signal="tls",
                why="TLS Alert 通常由证书链或协议套件不兼容引起，需要独立验证握手。",
            )

        if prioritized_actions:
            for idx, action in enumerate(prioritized_actions[:4], 1):
                action_text = str(action.get("action", "")).strip()
                if not action_text:
                    continue
                add_item(
                    f"执行优先动作{idx}（引擎建议）",
                    action_text,
                    "动作完成并记录证据，更新回归检查结果",
                    70 - idx,
                    why=f"来源：{str(action.get('source', '引擎建议'))}",
                )

        selected.sort(key=lambda x: int(x["priority"]), reverse=True)
        max_items = 7 if output_level <= 3 else (10 if output_level == 4 else 14)
        rows: List[Dict[str, str]] = []
        for idx, item in enumerate(selected[:max_items], 1):
            purpose = str(item["purpose"])
            command = str(item["command"])
            signal = str(item.get("signal", "mixed") or "mixed")
            tags = self._extract_signal_tags(purpose, str(item.get("why", "")), signal)
            if signal not in tags and signal not in {"", "mixed"}:
                tags.insert(0, signal)
            tags = self._dedupe_strings(tags)
            record_seed = f"{purpose}|{command}|{idx}"
            rows.append(
                {
                    "step": str(idx),
                    "purpose": purpose,
                    "command": command,
                    "expect": item["expect"],
                    "sample": str(item.get("sample", "") or ""),
                    "why": str(item.get("why", "") or ""),
                    "tags": tags,
                    "tag_keys": ",".join(tags),
                    "record_id": f"CMD-{hashlib.sha1(record_seed.encode('utf-8')).hexdigest()[:10]}",
                }
            )
        return rows

    def _build_regression_checks(self, metrics: Dict[str, Any], output_level: int = 3) -> List[Dict[str, str]]:
        cfg = metrics.get("config_thresholds") or self._extract_thresholds()
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}
        flow_analysis = metrics.get("flow_analysis", {}) or {}
        problem_flow_count = len(metrics.get("problem_flows", []) or [])
        total_flows = max(int(flow_analysis.get("total_flows", problem_flow_count) or problem_flow_count), 1)
        problem_flow_ratio = problem_flow_count / total_flows

        retrans_th = float(cfg.get("retransmission_rate", 0.05))
        rst_th = float(cfg.get("rst_rate", 0.02))
        http_th = float(cfg.get("http_error_rate", 0.1))
        dns_th = float(cfg.get("dns_failure_rate", 0.05))
        rtt_th = float(cfg.get("rtt_high_ms", cfg.get("rtt_threshold_ms", 500)))
        asym_th = float(cfg.get("asymmetry_ratio", 10))

        http_total = max(int(app.get("http_total", 0) or 0), 1)
        dns_total = max(int(app.get("dns_total", 0) or 0), 1)
        http_rate = float(app.get("http_error_responses", 0) or 0) / http_total
        dns_rate = float(app.get("dns_error_rcode", 0) or 0) / dns_total

        tcp_attempts = int(tcp.get("connection_attempts", 0) or 0)
        tcp_failed = int(tcp.get("connection_failures", 0) or 0)
        if tcp_attempts > 0:
            tcp_success = max(0.0, 1.0 - (tcp_failed / max(tcp_attempts, 1)))
            tcp_success_current = f"{tcp_success * 100:.2f}% ({max(tcp_attempts - tcp_failed, 0)}/{tcp_attempts})"
        else:
            tcp_success = max(0.0, 1.0 - problem_flow_ratio)
            tcp_success_current = f"{tcp_success * 100:.2f}% (估算)"

        checks: List[Dict[str, str]] = [
            {
                "check": "TCP重传率回归",
                "target": f"< {retrans_th * 100:.2f}%",
                "current": f"{float(tcp.get('retrans_rate', 0) or 0) * 100:.2f}%",
                "status": "通过" if float(tcp.get("retrans_rate", 0) or 0) < retrans_th else "未通过",
                "script": "tshark -r <new.pcap> -Y \"tcp.analysis.retransmission\" | wc -l",
            },
            {
                "check": "TCP RST率回归",
                "target": f"< {rst_th * 100:.2f}%",
                "current": f"{float(tcp.get('rst_rate', 0) or 0) * 100:.2f}%",
                "status": "通过" if float(tcp.get("rst_rate", 0) or 0) < rst_th else "未通过",
                "script": "tshark -r <new.pcap> -Y \"tcp.flags.reset==1\" | wc -l",
            },
            {
                "check": "HTTP错误率回归",
                "target": f"< {http_th * 100:.2f}%",
                "current": f"{http_rate * 100:.2f}%",
                "status": "通过" if http_rate < http_th else "未通过",
                "script": "tshark -r <new.pcap> -Y \"http.response.code >= 400\" | wc -l",
            },
            {
                "check": "DNS失败率回归",
                "target": f"< {dns_th * 100:.2f}%",
                "current": f"{dns_rate * 100:.2f}%",
                "status": "通过" if dns_rate < dns_th else "未通过",
                "script": "tshark -r <new.pcap> -Y \"dns.flags.rcode > 0\" | wc -l",
            },
        ]

        if output_level >= 5:
            checks.extend(
                [
                    {
                        "check": "平均RTT回归",
                        "target": f"< {rtt_th:.0f}ms",
                        "current": f"{float(tcp.get('avg_rtt', 0) or 0) * 1000:.0f}ms",
                        "status": "通过" if float(tcp.get("avg_rtt", 0) or 0) * 1000 < rtt_th else "未通过",
                        "script": "tshark -r <new.pcap> -Y \"tcp.analysis.ack_rtt\" -T fields -e tcp.analysis.ack_rtt",
                    },
                    {
                        "check": "问题流占比回归",
                        "target": "< 5.00%",
                        "current": f"{problem_flow_ratio * 100:.2f}% ({problem_flow_count}/{total_flows})",
                        "status": "通过" if problem_flow_ratio < 0.05 else "未通过",
                        "script": "python main.py analyze <new.pcap> --mode diagnosis --all --no-report",
                    },
                    {
                        "check": "流量对称性回归",
                        "target": f"<= {asym_th:.1f}:1",
                        "current": f"{float(net.get('asymmetry_ratio', 1) or 1):.1f}:1",
                        "status": "通过" if float(net.get("asymmetry_ratio", 1) or 1) <= asym_th else "未通过",
                        "script": "tshark -r <new.pcap> -q -z conv,tcp",
                    },
                    {
                        "check": "TCP连接成功率（探活基准）",
                        "target": ">= 95.00%",
                        "current": tcp_success_current,
                        "status": "通过" if tcp_success >= 0.95 else "未通过",
                        "script": "tshark -r <new.pcap> -Y \"tcp.flags.syn==1\" -T fields -e tcp.stream",
                    },
                ]
            )

        return checks

    @staticmethod
    def _build_resolution_plan(actions: List[Dict[str, str]], output_level: int = 3) -> List[Dict[str, str]]:
        _ = output_level
        plan: List[Dict[str, str]] = []
        for idx, item in enumerate(actions[:6], 1):
            phase = "定位" if idx <= 2 else ("修复" if idx <= 4 else "验证")
            if idx <= 2:
                difficulty = "中"
                eta = "20-40 分钟"
            elif idx <= 4:
                difficulty = "高"
                eta = "40-120 分钟"
            else:
                difficulty = "低"
                eta = "10-30 分钟"
            plan.append(
                {
                    "order": str(idx),
                    "phase": phase,
                    "action": str(item.get("action", "")),
                    "done_criteria": "关键指标回落且无新增高危告警",
                    "difficulty": difficulty,
                    "eta": eta,
                    "source": str(item.get("source", "未知来源")),
                }
            )
        return plan

    @staticmethod
    def _diagnosis_owner_profile(diagnosis: str) -> Tuple[str, str, str, str, str]:
        text = str(diagnosis or "")
        upper = text.upper()
        if "握手失败" in text or "握手未完成" in text or "SYN" in upper:
            return (
                "网络团队 + 安全团队",
                "核查目标端口监听、ACL/防火墙策略与会话表，定位握手中断点",
                "三次握手完整且连接建立成功率稳定",
                "中",
                "30-60 分钟",
            )
        if "重置" in text or "RST" in upper:
            return (
                "应用团队 + 安全团队",
                "核查服务端拒绝策略、WAF/IPS重置策略与连接上限",
                "RST比例回落至阈值内且连接不再异常中断",
                "中",
                "20-50 分钟",
            )
        if "窗口" in text or "ZERO" in upper:
            return (
                "系统团队 + 应用团队",
                "检查接收端CPU/内存/缓冲区，优化socket参数与消费速度",
                "ZeroWindow告警清零，吞吐与时延恢复稳定",
                "高",
                "40-120 分钟",
            )
        if "重传" in text or "丢包" in text or "抖动" in text or "延迟" in text:
            return (
                "网络团队",
                "定位链路丢包跳点，核查队列拥塞、光模块与接口错误计数",
                "重传率与时延回落到阈值内，链路无持续丢包",
                "高",
                "45-150 分钟",
            )
        if "DNS" in upper:
            return (
                "平台团队 + 网络团队",
                "核查本地与上游DNS递归链路、缓存命中与错误码分布",
                "DNS失败率回落至阈值内且解析时延稳定",
                "中",
                "20-60 分钟",
            )
        if "HTTP" in upper or "TLS" in upper:
            return (
                "应用团队",
                "排查上游依赖、证书与协议兼容，校验网关配置",
                "业务请求成功率恢复，错误码与握手失败显著下降",
                "中",
                "30-90 分钟",
            )
        return (
            "网络团队 + 应用团队",
            "按命令级清单逐层排查网络、策略与应用链路",
            "关键指标回落阈值内并通过业务探活验证",
            "中",
            "30-90 分钟",
        )

    def _build_diagnosis_casebook(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
        prioritized_actions: List[Dict[str, str]],
        limit: int = 12,
    ) -> List[Dict[str, str]]:
        flows = metrics.get("problem_flows", []) or []
        ranked = sorted(flows, key=self._flow_score, reverse=True)[: max(limit, 1)]
        casebook: List[Dict[str, str]] = []

        for idx, flow in enumerate(ranked, 1):
            endpoint = (
                f"{flow.get('src_ip', 'unknown')}:{int(flow.get('src_port', 0) or 0)}"
                f" -> {flow.get('dst_ip', 'unknown')}:{int(flow.get('dst_port', 0) or 0)}"
            )
            diagnosis = self._flow_diagnosis(flow)
            owner, action, verify, difficulty, eta = self._diagnosis_owner_profile(diagnosis)
            casebook.append(
                {
                    "case_id": f"INC-{idx:02d}",
                    "endpoint": endpoint,
                    "fault_signature": diagnosis,
                    "owner": owner,
                    "action": action,
                    "verify": verify,
                    "difficulty": difficulty,
                    "eta": eta,
                }
            )

        if not casebook and fault_locations:
            for idx, row in enumerate(fault_locations[: max(limit, 1)], 1):
                diagnosis = str(row.get("diagnosis", "异常"))
                owner, action, verify, difficulty, eta = self._diagnosis_owner_profile(diagnosis)
                if idx <= len(prioritized_actions):
                    candidate = str(prioritized_actions[idx - 1].get("action", "")).strip()
                    if candidate:
                        action = candidate
                casebook.append(
                    {
                        "case_id": f"INC-{idx:02d}",
                        "endpoint": str(row.get("endpoint", "抓包范围内")),
                        "fault_signature": diagnosis,
                        "owner": owner,
                        "action": action,
                        "verify": verify,
                        "difficulty": difficulty,
                        "eta": eta,
                    }
                )

        if not casebook and anomalies:
            for idx, anomaly in enumerate(anomalies[: max(limit, 1)], 1):
                diagnosis = str(anomaly.get("rule_name", "异常"))
                owner, action, verify, difficulty, eta = self._diagnosis_owner_profile(diagnosis)
                suggestions = anomaly.get("suggestions", []) or []
                if suggestions:
                    action = str(suggestions[0])
                casebook.append(
                    {
                        "case_id": f"INC-{idx:02d}",
                        "endpoint": "抓包范围内（未提取到明确端点）",
                        "fault_signature": diagnosis,
                        "owner": owner,
                        "action": action,
                        "verify": verify,
                        "difficulty": difficulty,
                        "eta": eta,
                    }
                )

        return casebook

    def _build_acceptance_checklist(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        cfg = metrics.get("config_thresholds") or self._extract_thresholds()
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}
        flow_analysis = metrics.get("flow_analysis", {}) or {}
        problem_flow_count = len(metrics.get("problem_flows", []) or [])
        total_flows = max(int(flow_analysis.get("total_flows", problem_flow_count) or problem_flow_count), 1)
        problem_flow_ratio = problem_flow_count / total_flows

        endpoint = fault_locations[0]["endpoint"] if fault_locations else "关键业务端点"
        retrans_th = float(cfg.get("retransmission_rate", 0.05))
        rst_th = float(cfg.get("rst_rate", 0.02))
        asym_th = float(cfg.get("asymmetry_ratio", 10))
        rtt_th = float(cfg.get("rtt_high_ms", cfg.get("rtt_threshold_ms", 500)))
        dns_th = float(cfg.get("dns_failure_rate", 0.05))
        http_success_th = float(cfg.get("http_success_rate", cfg.get("http_min_success_rate", 0.99)))

        http_total = max(int(app.get("http_total", 0) or 0), 1)
        dns_total = max(int(app.get("dns_total", 0) or 0), 1)
        http_rate = float(app.get("http_error_responses", 0) or 0) / http_total
        dns_rate = float(app.get("dns_error_rcode", 0) or 0) / dns_total
        http_success = 1.0 - http_rate

        checks: List[Dict[str, str]] = [
            {
                "item": "端到端连通性",
                "target": f"{endpoint} 持续探活成功",
                "method": "tcping/nc + 业务探活脚本",
                "status": "待验证",
            },
            {
                "item": "TCP重传率",
                "target": f"< {retrans_th * 100:.2f}%",
                "method": "抓包复测 + 指标平台核对",
                "status": "通过" if float(tcp.get("retrans_rate", 0) or 0) < retrans_th else "未通过",
            },
            {
                "item": "TCP RST率",
                "target": f"< {rst_th * 100:.2f}%",
                "method": "抓包复测 + 会话中断日志核对",
                "status": "通过" if float(tcp.get("rst_rate", 0) or 0) < rst_th else "未通过",
            },
            {
                "item": "平均RTT回归",
                "target": f"< {rtt_th:.0f}ms",
                "method": "抓包统计 avg_rtt / p95时延",
                "status": "通过" if float(tcp.get("avg_rtt", 0) or 0) * 1000 < rtt_th else "未通过",
            },
            {
                "item": "问题流占比",
                "target": "< 5.00%",
                "method": "问题流/总流量按同时间窗复算",
                "status": "通过" if problem_flow_ratio < 0.05 else "未通过",
            },
            {
                "item": "流量对称性",
                "target": f"<= {asym_th:.1f}:1",
                "method": "双向抓包 + 路由回程核验",
                "status": "通过" if float(net.get("asymmetry_ratio", 1) or 1) <= asym_th else "未通过",
            },
            {
                "item": "HTTP成功率",
                "target": f">= {http_success_th * 100:.2f}%",
                "method": "按状态码复盘 2xx/3xx/4xx/5xx",
                "status": "通过" if http_success >= http_success_th else "未通过",
            },
            {
                "item": "DNS失败率",
                "target": f"< {dns_th * 100:.2f}%",
                "method": "解析日志 + rcode分布核对",
                "status": "通过" if dns_rate < dns_th else "未通过",
            },
            {
                "item": "业务功能验收",
                "target": "核心交易/接口/页面全链路通过",
                "method": "执行业务回归用例（含高峰场景）",
                "status": "待验证",
            },
            {
                "item": "监控告警回归",
                "target": "无持续高危告警，阈值与路由正确",
                "method": "巡检监控看板 + 告警平台",
                "status": "待验证",
            },
        ]

        anomaly_text = " ".join([str(a.get("rule_name", "")) for a in anomalies]).upper()
        if "TLS" in anomaly_text:
            checks.append(
                {
                    "item": "TLS握手与证书链",
                    "target": "证书链完整，协议/套件匹配",
                    "method": "openssl s_client + 网关证书核对",
                    "status": "待验证",
                }
            )
        if "DNS" in anomaly_text:
            checks.append(
                {
                    "item": "DNS解析链路",
                    "target": "无SERVFAIL/NXDOMAIN异常峰值",
                    "method": "dig +trace + 解析日志核对",
                    "status": "待验证",
                }
            )
        return checks

    def _build_management_summary(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
        prioritized_actions: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        cfg = metrics.get("config_thresholds") or self._extract_thresholds()
        tcp = metrics.get("tcp", {}) or {}
        retrans_rate = float(tcp.get("retrans_rate", 0.0) or 0.0)
        rst_rate = float(tcp.get("rst_rate", 0.0) or 0.0)
        retrans_th = float(cfg.get("retransmission_rate", 0.05))
        rst_th = float(cfg.get("rst_rate", 0.02))
        critical_count = sum(1 for a in anomalies if str(a.get("severity_name", "")).upper() == "CRITICAL")
        high_count = sum(1 for a in anomalies if str(a.get("severity_name", "")).upper() == "HIGH")

        risk_level = "低"
        if critical_count > 0 or retrans_rate >= retrans_th * 1.5 or rst_rate >= rst_th * 1.5 or len(anomalies) >= 12:
            risk_level = "高"
        elif high_count > 0 or retrans_rate >= retrans_th or rst_rate >= rst_th or len(anomalies) >= 6:
            risk_level = "中"

        impact_scope = self._derive_impact_scope([], metrics, len(anomalies))
        if len(fault_locations) >= 5 and impact_scope == "局部影响":
            impact_scope = "全局影响"

        key_finding = "未发现明显异常"
        if fault_locations:
            top_fault = fault_locations[0]
            key_finding = f"{top_fault.get('endpoint', '未知')} -> {top_fault.get('diagnosis', '传输异常')}"
        elif anomalies:
            key_finding = str(anomalies[0].get("rule_name", "发现异常"))

        top_actions = [str(item.get("action", "")).strip() for item in prioritized_actions[:3] if str(item.get("action", "")).strip()]
        if not top_actions:
            top_actions = self._default_actions(risk_level)

        risk_class = "risk-low"
        if risk_level == "高":
            risk_class = "risk-high"
        elif risk_level == "中":
            risk_class = "risk-mid"
        return {
            "risk_level": risk_level,
            "risk_class": risk_class,
            "impact_scope": impact_scope,
            "key_finding": key_finding,
            "top_actions": top_actions,
        }

    @staticmethod
    def _derive_impact_scope(
        root_causes: List[Dict[str, Any]],
        metrics: Dict[str, Any],
        anomaly_count: int,
    ) -> str:
        if root_causes and str(root_causes[0].get("affected_scope", "")).strip():
            return str(root_causes[0].get("affected_scope", "")).strip()
        if anomaly_count <= 0:
            return "未发现明显异常"

        problem_flows = len(metrics.get("problem_flows", []) or [])
        total_flows = int((metrics.get("flow_analysis", {}) or {}).get("total_flows", 0) or 0)
        if problem_flows > 0 and total_flows > 0:
            ratio = problem_flows / max(total_flows, 1)
            if ratio >= 0.30:
                return "全局影响"
            if ratio >= 0.10:
                return "部分影响"
            return "局部影响"
        if problem_flows > 0:
            return f"涉及 {problem_flows} 条问题流"
        return "影响范围待进一步确认"

    @staticmethod
    def _default_actions(risk_level: str) -> List[str]:
        if risk_level == "高":
            return [
                "优先定位最高严重度异常对应主机与端口，先恢复业务连通性",
                "在故障链路两端执行双向抓包，确认中断位置",
                "同步核查防火墙/ACL/安全设备策略是否误拦截",
            ]
        if risk_level == "中":
            return [
                "按异常类型检查链路质量、端口状态与上游依赖",
                "补充关键时间段抓包并与正常时段做对比",
                "将重复出现的异常纳入监控阈值与告警基线",
            ]
        return [
            "当前风险较低，建议保持趋势监控",
            "对零星异常进行抽样复核",
            "保留报告用于后续基线对比",
        ]

    @staticmethod
    def _build_health_score(
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
        key_metric_rows: List[Dict[str, str]],
        management_summary: Dict[str, Any],
        business_impact: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compute an overall health score (0-100) for the capture session."""
        score = 100.0

        # Deductions from anomalies (capped to avoid score collapsing to 0 too easily)
        critical_count = sum(1 for a in anomalies if str(a.get("severity_name", "")).upper() == "CRITICAL")
        high_count = sum(1 for a in anomalies if str(a.get("severity_name", "")).upper() == "HIGH")
        medium_count = sum(1 for a in anomalies if str(a.get("severity_name", "")).upper() == "MEDIUM")
        low_count = sum(1 for a in anomalies if str(a.get("severity_name", "")).upper() == "LOW")
        anomaly_penalty = min(42.0, critical_count * 12.0 + high_count * 7.0 + medium_count * 3.0 + low_count * 1.0)
        score -= anomaly_penalty

        # Deductions from threshold breaches (capped)
        breached = sum(1 for row in key_metric_rows if str(row.get("status", "")) == "超阈值")
        threshold_penalty = min(24.0, breached * 4.0)
        score -= threshold_penalty

        # Deductions from fault locations (capped)
        high_impact = sum(1 for f in fault_locations if str(f.get("impact", "") or f.get("impact_label", "")) == "高")
        mid_impact = sum(1 for f in fault_locations if str(f.get("impact", "") or f.get("impact_label", "")) == "中")
        fault_penalty = min(20.0, high_impact * 8.0 + mid_impact * 3.0)
        score -= fault_penalty

        # Deductions from business impact
        business_penalty = 0.0
        if business_impact:
            impact_level = str(business_impact.get("impact_level", "") or "")
            if impact_level == "高":
                business_penalty = 10.0
            elif impact_level == "中":
                business_penalty = 4.0
        score -= business_penalty

        # Deductions from risk level
        risk_penalty = 0.0
        risk_level = str(management_summary.get("risk_level", "") or "")
        if risk_level == "高":
            risk_penalty = 8.0
        elif risk_level == "中":
            risk_penalty = 3.0
        score -= risk_penalty

        score = max(0, min(100, int(round(score))))

        if score >= 90:
            grade, label, grade_class = "A", "健康", "health-a"
        elif score >= 75:
            grade, label, grade_class = "B", "良好", "health-b"
        elif score >= 60:
            grade, label, grade_class = "C", "需关注", "health-c"
        elif score >= 40:
            grade, label, grade_class = "D", "异常", "health-d"
        else:
            grade, label, grade_class = "F", "严重", "health-f"

        return {
            "score": score,
            "grade": grade,
            "label": label,
            "grade_class": grade_class,
            "penalty_breakdown": {
                "anomaly": round(anomaly_penalty, 1),
                "threshold": round(threshold_penalty, 1),
                "fault": round(fault_penalty, 1),
                "business": round(business_penalty, 1),
                "risk": round(risk_penalty, 1),
            },
        }

    @classmethod
    def _build_report_profile(
        cls,
        anomalies: List[Dict[str, Any]],
        root_causes: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        domain_counter = Counter()
        for item in anomalies:
            label = cls._domain_label(f"{item.get('rule_name', '')} {item.get('description', '')}")
            domain_counter[label] += 1

        dominant_domain = "综合"
        if domain_counter:
            top_domain, top_count = domain_counter.most_common(1)[0]
            non_zero = sum(1 for _, v in domain_counter.items() if v > 0)
            if non_zero >= 2 and (top_count / max(len(anomalies), 1)) < 0.65:
                dominant_domain = "综合"
            else:
                dominant_domain = top_domain

        evidence_count = sum(len(item.get("evidence", []) or []) for item in anomalies)
        if evidence_count >= max(4, len(anomalies)):
            evidence_level = "充分"
        elif evidence_count > 0:
            evidence_level = "中等"
        else:
            evidence_level = "有限"

        top_conf = 0.0
        if root_causes:
            top_conf = max(float(item.get("confidence", 0.0) or 0.0) for item in root_causes)
        if top_conf >= 0.8:
            confidence_level = "高"
        elif top_conf >= 0.5:
            confidence_level = "中"
        else:
            confidence_level = "低"

        critical_count = sum(1 for item in anomalies if str(item.get("severity_name", "")).upper() == "CRITICAL")
        high_count = sum(1 for item in anomalies if str(item.get("severity_name", "")).upper() == "HIGH")
        return {
            "dominant_domain": dominant_domain,
            "evidence_level": evidence_level,
            "confidence_level": confidence_level,
            "critical_count": critical_count,
            "high_count": high_count,
            "anomaly_count": len(anomalies),
        }

    @classmethod
    def _build_mode_brief(
        cls,
        mode_key: str,
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
        report_profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _ = fault_locations
        profile = report_profile or cls._build_report_profile(anomalies, [])
        title = {
            "quick": "快速分析",
            "deep": "深度分析",
            "diagnosis": "故障诊断",
            "local": "本地分析",
        }.get(mode_key, "分析")
        problem_flow_count = len(metrics.get("problem_flows", []) or [])
        domain = str(profile.get("dominant_domain", "综合"))
        evidence_level = str(profile.get("evidence_level", "有限"))
        confidence_level = str(profile.get("confidence_level", "低"))
        high_risk = int(profile.get("critical_count", 0) or 0) + int(profile.get("high_count", 0) or 0)
        anomaly_count = len(anomalies)

        if anomaly_count <= 0:
            return {
                "title": title,
                "bullets": [
                    "本次未识别到明确异常，报告以健康基线与监控建议为主。",
                    f"分析覆盖问题流 {problem_flow_count} 条，证据完整度：{evidence_level}。",
                    "建议保留本报告作为后续故障对比样本。",
                ],
            }

        level = cls._output_level(mode_key)
        if level >= 5:
            bullets = [
                f"本次以{domain}异常为主，识别异常 {anomaly_count} 项（严重/高风险 {high_risk} 项），问题流 {problem_flow_count} 条。",
                f"根因推断置信度：{confidence_level}，证据完整度：{evidence_level}。",
                "报告已输出工单化处置、命令清单与验收闭环，可直接执行。",
            ]
        elif level == 4:
            bullets = [
                f"异常分布以{domain}为主，识别异常 {anomaly_count} 项，问题流 {problem_flow_count} 条。",
                f"当前根因置信度：{confidence_level}，建议先处理高影响故障点再做分层验证。",
                "深度模式已给出修复路径与回归检查建议，可用于闭环验证。",
            ]
        else:
            bullets = [
                f"本次快速定位到 {anomaly_count} 项异常，问题流 {problem_flow_count} 条，主异常域：{domain}。",
                f"证据完整度：{evidence_level}，根因置信度：{confidence_level}。",
                "适合应急场景先止血，后续可升级到深度/诊断模式补齐验证闭环。",
            ]
        return {"title": title, "bullets": bullets}


    @staticmethod
    def _build_smart_findings(
        metrics: Dict[str, Any],
        anomalies: List[Dict[str, Any]],
        root_causes: List[Dict[str, Any]],
        fault_locations: List[Dict[str, Any]],
        report_profile: Dict[str, Any],
        history_trend: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        if not anomalies:
            return ["本次抓包未发现明显异常，建议将该样本作为健康基线并持续对比。"]

        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}
        cfg = metrics.get("config_thresholds") or {}
        retrans_th = float(cfg.get("retransmission_rate", 0.05)) if cfg else 0.05
        rst_th = float(cfg.get("rst_rate", 0.02)) if cfg else 0.02

        domain = str(report_profile.get("dominant_domain", "综合"))
        high_risk = int(report_profile.get("critical_count", 0) or 0) + int(report_profile.get("high_count", 0) or 0)
        retrans_rate = float(tcp.get("retrans_rate", 0.0) or 0.0)
        rst_rate = float(tcp.get("rst_rate", 0.0) or 0.0)
        conf_level = str(report_profile.get("confidence_level", "低"))
        evidence_level = str(report_profile.get("evidence_level", "有限"))

        findings: List[str] = [
            f"异常主要集中在{domain}，共 {len(anomalies)} 项，其中严重/高风险 {high_risk} 项。",
        ]

        # ── 故障点定位 ──
        if fault_locations:
            top = fault_locations[0]
            findings.append(f"最高优先故障点位于 {top.get('endpoint', '未知端点')}，判定为「{top.get('diagnosis', '异常')}」。")

        # ── 关联推理：异常间因果链分析 ──
        anomaly_tags: Dict[str, int] = {}
        for an in anomalies:
            for tag in (an.get("tags", []) or []):
                anomaly_tags[tag] = anomaly_tags.get(tag, 0) + 1

        causal_chains: List[str] = []
        dns_err = int(app.get("dns_error_rcode", 0) or 0)
        http_err = int(app.get("http_error_responses", 0) or 0)
        handshake_faults = sum(
            1 for f in fault_locations
            if any(k in str(f.get("diagnosis", "")) for k in ["握手失败", "握手未完成"])
        )

        if dns_err > 0 and retrans_rate > retrans_th:
            causal_chains.append(f"DNS 解析异常（{dns_err} 次）可能导致连接超时与 TCP 重传升高（{retrans_rate * 100:.2f}%），建议优先排查 DNS 上游链路。")
        if retrans_rate > retrans_th and rst_rate > rst_th:
            causal_chains.append(f"重传率（{retrans_rate * 100:.2f}%）与 RST 率（{rst_rate * 100:.2f}%）同时超阈值，可能存在链路拥塞导致超时后被端点或安全设备重置。")
        if handshake_faults > 0 and rst_rate > rst_th:
            causal_chains.append(f"握手异常流 {handshake_faults} 条且 RST 率偏高，可能为防火墙/ACL 策略拦截或服务端口未监听。")
        if http_err > 0 and retrans_rate > retrans_th:
            causal_chains.append(f"HTTP 错误（{http_err} 次）与高重传并存，需区分是网络丢包导致请求失败还是应用本身异常。")
        if float(net.get("asymmetry_ratio", 1.0) or 1.0) > float(cfg.get("asymmetry_ratio", 10) if cfg else 10):
            causal_chains.append("流量不对称比偏高，可能存在回程路由异常或单向策略丢弃，建议双向抓包确认回包路径。")

        if causal_chains:
            findings.append(f"🔗 关联推理：{causal_chains[0]}")
            for chain in causal_chains[1:2]:
                findings.append(f"🔗 {chain}")

        # ── 历史对比变化亮点 ──
        if history_trend and history_trend.get("records"):
            delta_anomalies = int(history_trend.get("delta_anomalies", 0) or 0)
            delta_retrans = float(history_trend.get("delta_retrans_pct", 0.0) or 0.0)
            delta_rst = float(history_trend.get("delta_rst_pct", 0.0) or 0.0)
            trend_label = str(history_trend.get("trend_label", "") or "")
            parts: List[str] = []
            if delta_anomalies != 0:
                parts.append(f"异常数{'增加' if delta_anomalies > 0 else '减少'} {abs(delta_anomalies)} 项")
            if abs(delta_retrans) > 0.01:
                parts.append(f"重传率{'上升' if delta_retrans > 0 else '下降'} {abs(delta_retrans):.2f}%")
            if abs(delta_rst) > 0.01:
                parts.append(f"RST率{'上升' if delta_rst > 0 else '下降'} {abs(delta_rst):.2f}%")
            if parts:
                direction = "📈 恶化" if trend_label == "恶化" else ("📉 改善" if trend_label == "改善" else "➡️ 持平")
                findings.append(f"📊 与上次对比（{direction}）：{'；'.join(parts)}。")

        # ── 非预期发现：识别次要但值得关注的异常 ──
        unexpected: List[str] = []
        primary_domain_tags = set()
        for an in anomalies[:2]:
            for tag in (an.get("tags", []) or []):
                primary_domain_tags.add(tag)

        for an in anomalies[2:]:
            an_tags = set(an.get("tags", []) or [])
            if an_tags and not an_tags.intersection(primary_domain_tags):
                rule_name = str(an.get("rule_name", "") or "").strip()
                severity = str(an.get("severity_name", "") or "")
                if severity in ("CRITICAL", "HIGH", "MEDIUM") and rule_name:
                    unexpected.append(f"{rule_name}（{severity}）")

        if unexpected:
            findings.append(f"⚠️ 非预期发现：除主异常外，还存在跨域异常 —— {'；'.join(unexpected[:3])}，建议同步关注。")

        # ── 置信度与行动建议 ──
        if root_causes and conf_level != "低" and evidence_level != "有限":
            findings.append(f"当前根因推断置信度{conf_level}，证据完整度{evidence_level}，可直接按工单步骤执行。")
        elif root_causes:
            findings.append("当前根因置信度或证据完整度偏低，建议补充故障时段双向抓包与设备侧日志。")
        else:
            findings.append("暂未形成稳定根因，建议先按命令级清单补齐证据再做归因。")
        return findings[:10]


    @classmethod
    def _build_secondary_actions(
        cls,
        prioritized_actions: List[Dict[str, str]],
        top_actions: List[str],
    ) -> List[Dict[str, str]]:
        top_set = {cls._normalize_text(item) for item in top_actions if str(item or "").strip()}
        rows: List[Dict[str, str]] = []
        for item in prioritized_actions:
            action = str(item.get("action", "")).strip()
            if not action:
                continue
            if cls._normalize_text(action) in top_set:
                continue
            rows.append({"action": action, "source": str(item.get("source", "未知来源"))})
        return rows


    @staticmethod
    def _issue_domain(text: str) -> str:
        merged = str(text or "").upper()
        if not merged:
            return "none"
        if any(k in merged for k in ["重传", "RETRANS", "丢包", "DUP ACK", "FAST RETRANS"]):
            return "loss"
        if any(k in merged for k in ["握手", "SYN", "连接失败", "SYN-ACK"]):
            return "handshake"
        if any(k in merged for k in ["RST", "拦截", "ACL", "防火墙", "WAF", "IPS", "拒绝"]):
            return "policy"
        if any(k in merged for k in ["DNS", "NXDOMAIN", "SERVFAIL"]):
            return "dns"
        if any(k in merged for k in ["HTTP", "TLS", "5XX", "4XX"]):
            return "app"
        if any(k in merged for k in ["RTT", "延迟", "抖动", "JITTER", "卡慢"]):
            return "latency"
        if any(k in merged for k in ["PMTU", "MTU", "分片", "FRAG", "长度异常"]):
            return "mtu"
        if any(k in merged for k in ["中断", "单向", "NO_RESPONSE", "UNREACHABLE", "回程"]):
            return "interrupt"
        return "mixed"


    @classmethod
    def _build_local_result_smart(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        local = dict(data.get("local_result", {}) or {})
        anomalies = data.get("anomalies", []) or []
        fault_locations = data.get("fault_locations", []) or []
        root_causes = data.get("root_causes", []) or []
        management = data.get("management_summary", {}) or {}
        profile = data.get("report_profile", {}) or {}
        metrics = data.get("metrics", {}) or {}
        primary = data.get("primary_issue", {}) or {}

        label = str(primary.get("label", "") or "").strip()
        evidence = str(primary.get("evidence", "") or "").strip()
        action_hint = str(primary.get("action_hint", "") or "").strip()

        raw_summary = str(local.get("summary", "") or "").strip()
        raw_focus = cls._extract_issue_label(raw_summary) if raw_summary else ""
        primary_domain = cls._issue_domain(label)
        raw_domain = cls._issue_domain(raw_summary)
        conflict = (
            bool(raw_summary and label)
            and primary_domain not in {"none", "mixed"}
            and raw_domain not in {"none", "mixed"}
            and primary_domain != raw_domain
        )

        flow_count = len(metrics.get("problem_flows", []) or [])
        anomaly_count = len(anomalies)
        high_risk = int(profile.get("critical_count", 0) or 0) + int(profile.get("high_count", 0) or 0)
        top_fault_text = ""
        if fault_locations:
            top = fault_locations[0]
            top_fault_text = f"{top.get('endpoint', '未知端点')}（{top.get('diagnosis', '待确认')}）"

        if anomaly_count <= 0:
            summary = "当前未识别到稳定复现的故障信号，本次结果可作为健康基线。"
        else:
            core = label or "待进一步确认"
            evidence_text = evidence or "规则与指标存在异常，但需补充更多证据"
            summary = (
                f"核心问题：{core}。关键证据：{evidence_text}。"
                f"综合识别异常 {anomaly_count} 项（高风险 {high_risk} 项），涉及问题流 {flow_count} 条。"
            )
            if top_fault_text:
                summary += f" 当前首要影响点为 {top_fault_text}。"

        root_lines: List[str] = []
        if label:
            root_lines.append(f"综合判断：当前主导故障域为「{label}」。")
        if conflict:
            focus = raw_focus or raw_summary
            if len(focus) > 42:
                focus = focus[:41] + "…"
            root_lines.append(
                f"矛盾点：原始本地摘要偏向「{focus}」，但规则引擎与阈值证据显示「{label}」为主导问题。"
            )
        elif raw_summary and raw_summary != summary:
            supplemental = raw_focus or raw_summary
            if len(supplemental) > 42:
                supplemental = supplemental[:41] + "…"
            root_lines.append(f"补充线索：本地深度模式识别到「{supplemental}」，作为次级线索保留。")

        if root_causes:
            top_rc = root_causes[0]
            root_lines.append(
                f"根因候选：{top_rc.get('name', '待确认')}（置信度 {top_rc.get('confidence_percent', '--')}）"
            )
        if top_fault_text:
            root_lines.append(f"证据焦点：{top_fault_text}")
        if action_hint:
            root_lines.append(f"优先动作建议：{action_hint}")

        risk_map = {"高": "HIGH", "中": "MEDIUM", "低": "LOW"}
        risk = risk_map.get(str(management.get("risk_level", "") or ""), str(local.get("risk_level", "UNKNOWN") or "UNKNOWN"))

        confidence = float(local.get("confidence", 0.0) or 0.0)
        if root_causes:
            confidence = max(confidence, float(root_causes[0].get("confidence", 0.0) or 0.0))
        if anomaly_count > 0:
            confidence = max(confidence, 0.62 if high_risk > 0 else 0.55)
        confidence = min(confidence, 0.99)

        local["summary"] = summary
        local["root_cause"] = "\n".join(root_lines[:6]) if root_lines else str(local.get("root_cause", "") or "")
        local["risk_level"] = risk
        local["confidence"] = confidence
        return local


    @staticmethod
    def _build_local_result_fallback(data: Dict[str, Any]) -> Dict[str, Any]:
        anomalies = data.get("anomalies", []) or []
        fault_locations = data.get("fault_locations", []) or []
        root_causes = data.get("root_causes", []) or []
        metrics = data.get("metrics", {}) or {}

        management = data.get("management_summary", {}) or {}
        risk = "LOW"
        if management.get("risk_level") == "高":
            risk = "HIGH"
        elif management.get("risk_level") == "中":
            risk = "MEDIUM"

        flow_count = len(metrics.get("problem_flows", []) or [])
        top_issue = str(data.get("top_issue", "未发现明显异常") or "未发现明显异常")
        if anomalies:
            summary = f"{top_issue}；共发现 {len(anomalies)} 项异常，涉及 {flow_count} 条问题流。"
            if fault_locations:
                top = fault_locations[0]
                summary += f" 重点关注 {top.get('endpoint', '未知端点')}（{top.get('diagnosis', '待确认')}）。"
        else:
            summary = "未发现明显异常，当前抓包可作为健康基线。"

        root_lines: List[str] = []
        if root_causes:
            top_rc = root_causes[0]
            root_lines.append(f"综合判断：{top_rc.get('name', '待确认')}（置信度 {top_rc.get('confidence_percent', '--')}）")
        elif fault_locations:
            root_lines.append(f"综合判断：{fault_locations[0].get('diagnosis', '未发现明显根因')}")
        else:
            root_lines.append("综合判断：未发现明显根因")

        if fault_locations:
            top = fault_locations[0]
            root_lines.append(f"证据焦点：{top.get('endpoint', '未知端点')} -> {top.get('diagnosis', '待确认')}")

        confidence = 0.30
        if anomalies:
            confidence = 0.65
        if root_causes:
            confidence = max(float(root_causes[0].get("confidence", 0.0) or 0.0), confidence)

        return {
            "summary": summary,
            "root_cause": "\n".join(root_lines[:4]),
            "risk_level": risk,
            "confidence": confidence,
        }

    def _render_html(self, data: Dict[str, Any]) -> str:
        def esc(value: Any) -> str:
            text = str(value if value is not None else "")
            return (
                text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('\"', "&quot;")
            )

        fallback_warning = str(data.get("template_fallback_warning", "") or "").strip()

        rows = []
        for label, value in [
            ("File", data.get("file_name", "")),
            ("Generated", data.get("timestamp", "")),
            ("Mode", data.get("mode_label", "")),
            ("Total packets", data.get("total_packets", 0)),
            ("Total bytes", data.get("total_bytes", 0)),
            ("Duration (s)", f"{float(data.get('duration', 0) or 0):.2f}"),
        ]:
            rows.append(f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>")

        anomaly_items = []
        for row in data.get("anomalies", []) or []:
            anomaly_items.append(
                "<li>"
                f"{esc(row.get('rule_name', ''))} | severity={esc(row.get('severity_name', ''))} | "
                f"count={esc(row.get('count', 0))}"
                "</li>"
            )
        if not anomaly_items:
            anomaly_items.append("<li>No anomalies detected.</li>")

        root_cause_items = []
        for row in data.get("root_causes", []) or []:
            root_cause_items.append(
                "<li>"
                f"{esc(row.get('name', ''))} ({esc(row.get('confidence_percent', ''))})"
                "</li>"
            )
        if not root_cause_items:
            root_cause_items.append("<li>No root cause inferred.</li>")

        chart_blocks = []
        charts = data.get("charts", {}) or {}
        for title, key in [
            ("Transport Protocol Distribution", "protocol_pie"),
            ("Application Protocol Distribution", "app_protocol_pie"),
            ("Top IPs", "top_ips_bar"),
            ("TCP Metrics", "tcp_metrics_bar"),
            ("Traffic Timeline", "traffic_timeline"),
            ("IP Topology", "ip_topology"),
            ("Flow Fault Timeline", "flow_fault_timeline"),
        ]:
            html_block = charts.get(key, "")
            if html_block:
                chart_blocks.append(f"<h3>{esc(title)}</h3>{html_block}")

        warning_block = ""
        if fallback_warning:
            warning_block = (
                "<section>"
                "<h2 style='color:#b45309'>Template Fallback Warning</h2>"
                f"<p>{esc(fallback_warning)}</p>"
                "</section>"
            )

        return (
            "<html><head><meta charset='utf-8'><title>PCAP Report</title>"
            "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;}table{border-collapse:collapse;}th,td{border:1px solid #ddd;padding:8px;}th{text-align:left;background:#f5f5f5;}section{margin-top:24px;}ul{margin:8px 0 0 20px;}</style>"
            "</head><body>"
            f"<h1>PCAP Analysis Report - {esc(data.get('file_name', ''))}</h1>"
            + warning_block
            + "<section><h2>Summary</h2><table>"
            + "".join(rows)
            + "</table></section>"
            + "<section><h2>Anomalies</h2><ul>"
            + "".join(anomaly_items)
            + "</ul></section>"
            + "<section><h2>Root Causes</h2><ul>"
            + "".join(root_cause_items)
            + "</ul></section>"
            + (f"<section><h2>Charts</h2>{''.join(chart_blocks)}</section>" if chart_blocks else "")
            + "</body></html>"
        )

    def _generate_html(self, data: Dict[str, Any], base_name: str, timestamp: str) -> str:
        html_path = self.output_dir / f"report_{base_name}_{timestamp}.html"
        html_content = self._render_template_html(data)
        html_path.write_text(html_content, encoding="utf-8")
        return str(html_path)

    def _render_template_html(self, data: Dict[str, Any]) -> str:
        if self.jinja_env is not None:
            try:
                template = self.jinja_env.get_template("report.html")
                return template.render(**data)
            except Exception as exc:
                logger.error(f"Template render failed, fallback to minimal HTML: {exc}", exc_info=True)
                fallback_data = dict(data)
                fallback_data["template_fallback_warning"] = (
                    f"模板渲染失败，已自动回退到简化HTML。错误: {exc}"
                )
                return self._render_html(fallback_data)
        fallback_data = dict(data)
        fallback_data["template_fallback_warning"] = "未找到HTML模板，已自动回退到简化HTML。"
        return self._render_html(fallback_data)

    def _generate_markdown(self, data: Dict[str, Any], base_name: str, timestamp: str) -> str:
        lines: List[str] = []

        # ── Header ──
        lines.append(f"# PCAP 分析报告 - {data.get('file_name', '')}")
        lines.append("")
        mode_label = data.get("mode_label", "")
        risk_level = ""
        risk_class = ""
        mgmt = data.get("management_summary") or {}
        if mgmt:
            risk_level = str(mgmt.get("risk_level", "") or "")
            risk_class = str(mgmt.get("risk_class", "") or "")
        top_issue = data.get("top_issue") or "未发现明显异常"
        lines.append(f"> **模式**：{mode_label} | **风险等级**：{risk_level or '未知'} | **最关键问题**：{top_issue}")
        lines.append("")
        lines.append(f"- 文件名：{data.get('file_name', '')}")
        lines.append(f"- 分析时间：{data.get('timestamp', '')}")
        lines.append(f"- 分析范围：{data.get('analysis_scope_desc', 'all traffic')}")
        lines.append(f"- 总包数：{data.get('total_packets', 0):,}")
        lines.append(f"- 过滤命中：{data.get('analysis_scope_matched_packets', 0):,}/{data.get('analysis_scope_input_packets', 0):,} ({float(data.get('analysis_scope_ratio', 0) or 0) * 100:.2f}%)")
        lines.append(f"- 持续时间：{float(data.get('duration', 0) or 0):.2f}s")
        lines.append(f"- 总字节数：{data.get('total_bytes', 0):,}")
        lines.append("")

        # ── Smart Findings / 智能解读 ──
        smart_findings = data.get("smart_findings") or []
        if smart_findings:
            lines.append("## 智能解读")
            lines.append("")
            report_profile = data.get("report_profile") or {}
            if report_profile:
                lines.append(
                    f"> 主异常域：{report_profile.get('dominant_domain', '-')} | "
                    f"证据完整度：{report_profile.get('evidence_level', '-')} | "
                    f"根因置信度：{report_profile.get('confidence_level', '-')}"
                )
                lines.append("")
            for item in smart_findings:
                lines.append(f"- {item}")
            lines.append("")

        # ── 问题摘要（Quick Action Card） ──
        qac = data.get("quick_action_card")
        if qac:
            lines.append("## 问题摘要")
            lines.append("")
            lines.append(f"- **结论**：{qac.get('conclusion', '-')}")
            lines.append(f"- **影响**：{qac.get('impact', '-')}")
            qac_steps = qac.get("steps") or []
            if qac_steps:
                lines.append("- **快速行动**：")
                for step in qac_steps:
                    lines.append(f"  - {step}")
            else:
                lines.append("- **快速行动**：-")
            success_criteria = qac.get("success_criteria") or []
            if success_criteria:
                lines.append("- **成功判据**：")
                for sc in success_criteria:
                    lines.append(f"  - {sc}")
            lines.append("")

        # ── 业务影响量化 ──
        biz = data.get("business_impact")
        if biz:
            lines.append("## 业务影响量化")
            lines.append("")
            lines.append(biz.get("headline", ""))
            lines.append("")
            cards = biz.get("cards") or []
            if cards:
                for card in cards:
                    status_marker = "🔴" if "偏高" in str(card.get("status", "")) or "需" in str(card.get("status", "")) else "🟢"
                    lines.append(f"- {status_marker} **{card.get('label', '')}**：{card.get('value', '-')}（{card.get('status', '-')}）")
                lines.append("")

        # ── 关键指标 ──
        key_metric_rows = data.get("key_metric_rows") or []
        if key_metric_rows:
            lines.append("## 关键指标")
            lines.append("")
            lines.append("| 指标 | 当前值 | 阈值 | 状态 |")
            lines.append("|------|--------|------|------|")
            for row in key_metric_rows:
                status_icon = "🔴" if str(row.get("status", "")) == "超阈值" else "🟢"
                lines.append(f"| {row.get('metric', '')} | {row.get('current', '')} | {row.get('threshold', '')} | {status_icon} {row.get('status', '')} |")
            lines.append("")

        # ── 故障流详情 ──
        fault_flows = data.get("fault_flow_details") or []
        if fault_flows:
            lines.append("## 故障流详情")
            lines.append("")
            lines.append("| # | 故障点 | 判定 | 影响级别 | 握手阶段 | 传输阶段 | 关键证据 |")
            lines.append("|---|--------|------|----------|----------|----------|----------|")
            for row in fault_flows:
                impact_icon = "🔴" if str(row.get("impact_label", "")) == "高" else ("🟡" if str(row.get("impact_label", "")) == "中" else "🟢")
                lines.append(
                    f"| {row.get('rank', '')} | "
                    f"{row.get('endpoint', '')} | "
                    f"{row.get('diagnosis', '')} | "
                    f"{impact_icon} {row.get('impact_label', '')} | "
                    f"{row.get('handshake', '')} | "
                    f"{row.get('transfer', '')} | "
                    f"{row.get('evidence_compact', '')} |"
                )
            lines.append("")

        # ── 排障决策树 ──
        decision_tree = data.get("decision_tree") or []
        if decision_tree:
            lines.append("## 排障决策树")
            lines.append("")
            lines.append("| 步骤 | 判断问题 | 是 | 否 | 原因说明 |")
            lines.append("|------|----------|----|----|----------|")
            for row in decision_tree:
                lines.append(
                    f"| {row.get('step', '')} | "
                    f"{row.get('question', '')} | "
                    f"{row.get('if_yes', '')} | "
                    f"{row.get('if_no', '')} | "
                    f"{row.get('reason', '')} |"
                )
            lines.append("")

        # ── 命令级排查清单 ──
        cmd_checklist = data.get("command_checklist") or []
        if cmd_checklist:
            lines.append("## 命令级排查清单")
            lines.append("")
            lines.append(f"> 执行进度：0/{len(cmd_checklist)}")
            lines.append("")
            lines.append("| 步骤 | 目的 | 命令 | 预期结果 |")
            lines.append("|------|------|------|----------|")
            for row in cmd_checklist:
                command_text = str(row.get("command", "")).replace("\n", " ; ")
                lines.append(
                    f"| {row.get('step', '')} | "
                    f"{row.get('purpose', '')} | "
                    f"`{command_text}` | "
                    f"{row.get('expect', '')} |"
                )
            lines.append("")

        # ── 流量时间轴异常窗口 ──
        timeline_insights = data.get("timeline_insights") or []
        if timeline_insights:
            lines.append("## 流量时间轴异常窗口")
            lines.append("")
            lines.append("| 窗口 | 时间范围 | 包速(pkt/s) | 吞吐(Mbps) | 重传率 | RST率 | 平均RTT(ms) | 等级 |")
            lines.append("|------|----------|-------------|------------|--------|-------|-------------|------|")
            for row in timeline_insights:
                severity_icon = "🔴" if str(row.get("severity", "")) == "高" else ("🟡" if str(row.get("severity", "")) == "中" else "🟢")
                lines.append(
                    f"| {row.get('window', '')} | "
                    f"{row.get('range', '')} | "
                    f"{row.get('packets_per_sec', '')} | "
                    f"{row.get('throughput_mbps', '')} | "
                    f"{row.get('retrans_rate', '')} | "
                    f"{row.get('rst_rate', '')} | "
                    f"{row.get('avg_rtt_ms', '')} | "
                    f"{severity_icon} {row.get('severity', '')} |"
                )
            lines.append("")

        # ── 根因分析 ──
        root_causes = data.get("root_causes") or []
        if root_causes:
            lines.append("## 根因分析")
            lines.append("")
            for idx, rc in enumerate(root_causes, 1):
                lines.append(f"### {idx}. {rc.get('name', '未知')}（置信度 {rc.get('confidence_percent', '-')}）")
                lines.append("")
                if rc.get("summary"):
                    lines.append(f"**摘要**：{rc['summary']}")
                    lines.append("")
                if rc.get("affected_scope"):
                    lines.append(f"**影响范围**：{rc['affected_scope']}")
                    lines.append("")
                evidence = rc.get("evidence") or []
                if evidence:
                    lines.append("**证据**：")
                    for ev in evidence[:6]:
                        lines.append(f"- {ev}")
                    lines.append("")
                suggestions = rc.get("suggestions") or []
                if suggestions:
                    lines.append("**建议**：")
                    for sg in suggestions:
                        lines.append(f"- {sg}")
                    lines.append("")

        # ── 异常详情 ──
        anomalies = data.get("anomalies") or []
        if anomalies:
            lines.append("## 异常详情（按严重度排序）")
            lines.append("")
            for anomaly in anomalies:
                severity_icon = "🔴" if str(anomaly.get("severity_name", "")) in ("CRITICAL", "HIGH") else ("🟡" if str(anomaly.get("severity_name", "")) == "MEDIUM" else "🟢")
                lines.append(f"### {severity_icon} {anomaly.get('rule_name', '未知')}（{anomaly.get('severity', '未知')}）")
                lines.append("")
                if anomaly.get("description"):
                    lines.append(f"**描述**：{anomaly['description']}")
                    lines.append("")
                lines.append(f"**影响计数**：{anomaly.get('count', 0)} | **异常域**：{anomaly.get('domain', '-')}")
                lines.append("")
                threshold_rows = anomaly.get("threshold_rows") or []
                if threshold_rows:
                    lines.append("| 指标 | 实测值 | 阈值 | 结果 |")
                    lines.append("|------|--------|------|------|")
                    for tr in threshold_rows:
                        status_icon = "🔴" if str(tr.get("status", "")) == "超阈值" else "🟢"
                        lines.append(f"| {tr.get('metric', '')} | {tr.get('actual', '')} | {tr.get('threshold', '')} | {status_icon} {tr.get('status', '')} |")
                    lines.append("")
                evidence = anomaly.get("evidence") or []
                if evidence:
                    lines.append("**证据**：")
                    for ev in evidence[:6]:
                        lines.append(f"- {ev}")
                    lines.append("")
                suggestions = anomaly.get("suggestions") or []
                if suggestions:
                    lines.append("**建议**：")
                    for sg in suggestions:
                        lines.append(f"- {sg}")
                    lines.append("")

        # ── 回归检查 ──
        regression_checks = data.get("regression_checks") or []
        if regression_checks:
            lines.append("## 回归检查")
            lines.append("")
            lines.append("| 检查项 | 目标阈值 | 当前值 | 状态 |")
            lines.append("|--------|----------|--------|------|")
            for row in regression_checks:
                status_icon = "🔴" if str(row.get("status", "")) == "未通过" else ("🟢" if str(row.get("status", "")) == "通过" else "⚪")
                lines.append(f"| {row.get('check', '')} | {row.get('target', '')} | {row.get('current', '')} | {status_icon} {row.get('status', '')} |")
            lines.append("")

        # ── 分析结论 ──
        local_result = data.get("local_result")
        ai_result = data.get("ai_result")
        if local_result or ai_result:
            lines.append("## 分析结论")
            lines.append("")
            if local_result:
                lines.append("### 本地分析结论")
                lines.append("")
                lines.append(f"- **风险等级**：{local_result.get('risk_level', '-')}")
                lines.append(f"- **置信度**：{float(local_result.get('confidence', 0) or 0) * 100:.0f}%")
                lines.append(f"- **核心问题**：{local_result.get('summary', '-')}")
                root_cause_text = str(local_result.get("root_cause", "") or "").strip()
                if root_cause_text:
                    lines.append(f"- **根因说明**：")
                    for rc_line in root_cause_text.split("\n"):
                        rc_line = rc_line.strip()
                        if rc_line:
                            lines.append(f"  - {rc_line}")
                lines.append("")
            if ai_result:
                lines.append("### AI 分析结论")
                lines.append("")
                lines.append(f"- **风险等级**：{ai_result.get('risk_level', '-')}")
                lines.append(f"- **置信度**：{float(ai_result.get('confidence', 0) or 0) * 100:.0f}%")
                lines.append(f"- **核心问题**：{ai_result.get('summary', '-')}")
                if ai_result.get("root_cause"):
                    lines.append("- **根因说明**：")
                    for rc_line in str(ai_result.get("root_cause", "")).split("\n"):
                        rc_line = rc_line.strip()
                        if rc_line:
                            lines.append(f"  - {rc_line}")
                affected = ai_result.get("affected_systems") or []
                if affected:
                    lines.append("- **受影响对象**：")
                    for item in affected:
                        lines.append(f"  - {item}")
                steps = ai_result.get("troubleshooting_steps") or []
                if steps:
                    lines.append("- **AI建议排查步骤**：")
                    for idx, step in enumerate(steps, 1):
                        lines.append(f"  {idx}. {step}")
                prevention = ai_result.get("prevention") or []
                if prevention:
                    lines.append("- **AI预防建议**：")
                    for item in prevention:
                        lines.append(f"  - {item}")
                lines.append("")

        md_path = self.output_dir / f"report_{base_name}_{timestamp}.md"
        md_path.write_text("\n".join(lines), encoding="utf-8")
        return str(md_path)

    def _generate_json(self, data: Dict[str, Any], base_name: str, timestamp: str) -> List[str]:
        """Generate JSON reports: full version and a clean user-facing version."""
        generated: List[str] = []

        # Full version
        full_path = self.output_dir / f"report_{base_name}_{timestamp}.json"
        full_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        generated.append(str(full_path))

        # Clean user-facing version (exclude internal-only fields)
        clean_keys = {
            "file_path", "file_name", "timestamp", "mode_key", "mode_label", "output_level",
            "total_packets", "duration", "total_bytes",
            "analysis_scope_mode", "analysis_scope_ip", "analysis_scope_desc",
            "analysis_scope_input_packets", "analysis_scope_matched_packets", "analysis_scope_ratio",
            "has_issues", "is_ai",
            "top_issue", "primary_issue",
            "key_metrics", "prioritized_actions",
            "fault_locations", "flow_interactions", "fault_flow_details",
            "command_checklist", "regression_checks", "resolution_plan",
            "diagnosis_casebook", "acceptance_checklist",
            "management_summary", "report_profile", "report_fingerprint",
            "smart_findings", "incident_snapshot",
            "key_metric_rows", "timeline_insights", "decision_tree",
            "pmtu_samples", "chart_fallback_summary",
            "history_trend", "mode_brief", "secondary_actions",
            "show_prioritized_actions",
            "quick_action_card", "evidence_traces",
            "anomaly_groups", "confidence_explainer",
            "blind_spots", "report_diff",
            "business_impact", "closure_score",
            "attachments", "lightweight_mode_default", "chart_segments",
            "health_score",
            # Results
            "metrics", "anomalies", "root_causes",
            "ai_result", "local_result",
        }
        clean_data: Dict[str, Any] = {}
        for key, value in data.items():
            if key in clean_keys:
                clean_data[key] = value

        clean_path = self.output_dir / f"report_{base_name}_{timestamp}_clean.json"
        clean_path.write_text(
            json.dumps(clean_data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        generated.append(str(clean_path))
        return generated

    def _build_follow_stream_rows(
        self,
        metrics: Dict[str, Any],
        limit: int = 0,
        output_level: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retained for backward compatibility; Follow Stream output is disabled."""
        _ = (metrics, limit, output_level)
        return []
