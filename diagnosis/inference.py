"""Root cause inference engine."""

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from diagnosis.engine import Anomaly, Severity


@dataclass
class RootCause:
    """Root cause candidate."""

    name: str
    confidence: float  # 0~1
    evidence: List[str]
    affected_scope: str
    suggestions: List[str]
    related_anomalies: List[str]


class InferenceEngine:
    """Infer likely root causes from anomalies + metrics."""

    def __init__(self):
        self.root_cause_patterns = self._init_patterns()

    @staticmethod
    def _init_patterns() -> List[Dict[str, Any]]:
        return [
            {
                "name": "链路拥塞/丢包抖动",
                "category": "loss",
                "triggers": ["重传", "丢包", "延迟", "抖动", "卡慢", "DUP ACK", "FAST RETRANS"],
                "confidence_base": 0.86,
                "suggestions": [
                    "检查链路CRC、丢包和接口错误计数",
                    "检查队列拥塞/QoS策略与带宽利用率",
                    "对比高峰与低峰路径时延抖动",
                ],
            },
            {
                "name": "服务端可用性/端口异常",
                "category": "handshake",
                "triggers": ["握手失败", "连接失败", "SYN后无SYN-ACK", "SYN-ACK后无ACK", "半开"],
                "confidence_base": 0.90,
                "suggestions": [
                    "核查服务进程与端口监听状态",
                    "核查SYN/SYN-ACK回程路径与ACL",
                    "结合服务日志定位拒绝/超时原因",
                ],
            },
            {
                "name": "安全策略拦截",
                "category": "policy",
                "triggers": ["RST", "重置", "拦截", "ACL", "防火墙", "WAF", "IPS", "拒绝"],
                "confidence_base": 0.84,
                "suggestions": [
                    "检查安全设备策略命中与阻断日志",
                    "双向抓包确认阻断发生点",
                    "核对NAT/回程策略一致性",
                ],
            },
            {
                "name": "路径MTU/分片异常",
                "category": "mtu",
                "triggers": ["PMTU", "MTU", "分片", "FRAG", "长度异常", "Fragmentation Needed"],
                "confidence_base": 0.88,
                "suggestions": [
                    "执行路径MTU探测，确认可达包长",
                    "核查ICMP Fragmentation Needed是否被过滤",
                    "必要时启用MSS钳制缓解黑洞",
                ],
            },
            {
                "name": "DNS解析链路异常",
                "category": "dns",
                "triggers": ["DNS", "NXDOMAIN", "SERVFAIL", "解析失败", "DNS失败率"],
                "confidence_base": 0.80,
                "suggestions": [
                    "检查本地DNS转发和上游递归可达性",
                    "核查权威DNS响应与缓存策略",
                    "按错误码分布定位集中失败域",
                ],
            },
            {
                "name": "应用层响应异常",
                "category": "app",
                "triggers": ["HTTP", "TLS", "5XX", "4XX", "请求失败", "应用错误"],
                "confidence_base": 0.78,
                "suggestions": [
                    "按HTTP状态码和上游依赖分层定位",
                    "核查TLS证书链和协议兼容性",
                    "区分网络问题与应用处理瓶颈",
                ],
            },
        ]

    @staticmethod
    def _anomaly_text(anomaly: Anomaly) -> str:
        chunks = [
            str(getattr(anomaly, "rule_name", "") or ""),
            str(getattr(anomaly, "description", "") or ""),
        ]
        evidence = list(getattr(anomaly, "evidence", []) or [])
        if evidence:
            chunks.extend([str(item) for item in evidence[:6]])
        return " ".join([part for part in chunks if part.strip()])

    @staticmethod
    def _severity_score(level: Severity) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }.get(level, 1)

    @staticmethod
    def _keyword_signal_category(text: str) -> List[str]:
        merged = str(text or "").upper()
        categories: List[str] = []
        if any(k in merged for k in ["RETRANS", "重传", "丢包", "DUP ACK", "FAST RETRANS", "JITTER", "抖动", "延迟", "卡慢"]):
            categories.append("loss")
        if any(k in merged for k in ["SYN", "握手", "连接失败", "SYN-ACK", "半开"]):
            categories.append("handshake")
        if any(k in merged for k in ["RST", "重置", "拦截", "ACL", "防火墙", "WAF", "IPS", "拒绝"]):
            categories.append("policy")
        if any(k in merged for k in ["PMTU", "MTU", "分片", "FRAG", "LENGTH", "FRAGMENTATION NEEDED"]):
            categories.append("mtu")
        if any(k in merged for k in ["DNS", "NXDOMAIN", "SERVFAIL"]):
            categories.append("dns")
        if any(k in merged for k in ["HTTP", "TLS", "5XX", "4XX", "REQUEST FAILED"]):
            categories.append("app")
        return categories or ["generic"]

    @classmethod
    def _derive_signal_scores(cls, anomalies: List[Anomaly]) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        for anomaly in anomalies:
            sev = cls._severity_score(getattr(anomaly, "severity", Severity.LOW))
            count = float(getattr(anomaly, "count", 0) or 0)
            weight = max(1.0, float(sev)) + min(count / 20.0, 3.0)
            text = cls._anomaly_text(anomaly)
            for cat in cls._keyword_signal_category(text):
                scores[cat] = float(scores.get(cat, 0.0) + weight)
        return scores

    @staticmethod
    def _metric_support(category: str, metrics: Dict[str, Any]) -> Tuple[float, List[str]]:
        tcp = metrics.get("tcp", {}) or {}
        net = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}

        retrans = float(tcp.get("retrans_rate", 0) or 0)
        rst = float(tcp.get("rst_rate", 0) or 0)
        max_rtt_ms = float(tcp.get("max_rtt", 0) or 0) * 1000.0
        dup_ack = int(tcp.get("dup_ack", 0) or 0)
        frag_needed = int(net.get("icmp_frag_needed", 0) or 0)
        asym = float(net.get("asymmetry_ratio", 1.0) or 1.0)

        dns_total = max(int(app.get("dns_total", 0) or 0), 1)
        dns_err = int(app.get("dns_error_rcode", 0) or 0)
        dns_rate = dns_err / dns_total

        http_total = max(int(app.get("http_total", 0) or 0), 1)
        http_err = int(app.get("http_error_responses", 0) or 0)
        http_rate = http_err / http_total
        tls_alerts = int(app.get("tls_alerts", 0) or 0)

        score = 0.0
        evidence: List[str] = []

        if category == "loss":
            if retrans > 0.05:
                score += min(retrans / 0.05, 3.0)
                evidence.append(f"TCP重传率 {retrans * 100:.2f}% > 5%")
            if max_rtt_ms > 500:
                score += min(max_rtt_ms / 500.0, 2.5)
                evidence.append(f"RTT峰值 {max_rtt_ms:.0f}ms > 500ms")
            if dup_ack >= 3:
                score += min(dup_ack / 5.0, 2.0)
                evidence.append(f"重复ACK {dup_ack} 次")

        elif category == "handshake":
            syn = int(tcp.get("syn", 0) or 0)
            syn_ack = int(tcp.get("syn_ack", 0) or 0)
            attempts = int(tcp.get("connection_attempts", 0) or 0)
            fails = int(tcp.get("connection_failures", 0) or 0)
            if syn > syn_ack and syn > 0:
                score += min((syn - syn_ack) / max(syn, 1) * 4.0, 3.0)
                evidence.append("SYN 与 SYN-ACK 不匹配")
            if attempts > 0 and fails > 0:
                fail_rate = fails / max(attempts, 1)
                score += min(fail_rate * 4.0, 2.8)
                evidence.append(f"连接失败率 {fail_rate * 100:.2f}%")

        elif category == "policy":
            if rst > 0.02:
                score += min(rst / 0.02, 3.0)
                evidence.append(f"TCP RST率 {rst * 100:.2f}% > 2%")
            if asym > 10:
                score += min(asym / 10.0, 2.0)
                evidence.append(f"流量不对称比 {asym:.1f}:1")

        elif category == "mtu":
            if frag_needed > 0:
                score += min(frag_needed / 3.0, 3.0)
                evidence.append(f"ICMP Fragmentation Needed {frag_needed} 个")
            if int(tcp.get("frag_issue_flows", 0) or 0) > 0:
                score += 1.8
                evidence.append(f"分片异常流 {int(tcp.get('frag_issue_flows', 0) or 0)} 条")
            if int(tcp.get("length_issue_flows", 0) or 0) > 0:
                score += 1.2
                evidence.append(f"长度异常流 {int(tcp.get('length_issue_flows', 0) or 0)} 条")

        elif category == "dns":
            if dns_rate > 0.05:
                score += min(dns_rate / 0.05, 3.0)
                evidence.append(f"DNS失败率 {dns_rate * 100:.2f}% > 5%")
            if dns_err > 0:
                score += min(dns_err / 3.0, 2.0)
                evidence.append(f"DNS错误响应 {dns_err} 次")

        elif category == "app":
            if http_rate > 0.10:
                score += min(http_rate / 0.10, 3.0)
                evidence.append(f"HTTP错误率 {http_rate * 100:.2f}% > 10%")
            if tls_alerts > 0:
                score += min(tls_alerts / 3.0, 2.0)
                evidence.append(f"TLS Alert {tls_alerts} 次")
            if dns_err > 0:
                score += 0.6
                evidence.append("存在DNS错误，可能传导至应用失败")

        return score, evidence

    @staticmethod
    def _signal_support(category: str, signal_scores: Dict[str, float]) -> Tuple[float, List[str]]:
        score = float(signal_scores.get(category, 0.0) or 0.0)
        if category != "generic":
            score += float(signal_scores.get("generic", 0.0) or 0.0) * 0.15
        evidence = [f"异常信号强度[{category}]={score:.2f}"] if score > 0 else []
        return score, evidence

    def _collect_triggered_anomalies(self, anomalies: List[Anomaly], matched_triggers: List[str]) -> List[Anomaly]:
        if not matched_triggers:
            return []
        rows: List[Anomaly] = []
        for anomaly in anomalies:
            text = self._anomaly_text(anomaly)
            if any(trigger in text for trigger in matched_triggers):
                rows.append(anomaly)
        return rows

    @classmethod
    def _collect_category_anomalies(cls, anomalies: List[Anomaly], category: str) -> List[Anomaly]:
        if category == "generic":
            return list(anomalies)
        rows: List[Anomaly] = []
        for anomaly in anomalies:
            if category in cls._keyword_signal_category(cls._anomaly_text(anomaly)):
                rows.append(anomaly)
        return rows

    def infer(self, anomalies: List[Anomaly], metrics: Dict[str, Any]) -> List[RootCause]:
        """Infer top root causes."""
        if not anomalies:
            return []

        root_causes: List[RootCause] = []
        anomaly_texts = [self._anomaly_text(a) for a in anomalies]
        critical_count = sum(1 for a in anomalies if a.severity == Severity.CRITICAL)
        high_count = sum(1 for a in anomalies if a.severity == Severity.HIGH)
        signal_scores = self._derive_signal_scores(anomalies)

        for pattern in self.root_cause_patterns:
            triggers = pattern.get("triggers", []) or []
            category = str(pattern.get("category", "generic") or "generic")
            matched_triggers = [t for t in triggers if any(t in text for text in anomaly_texts)]
            matched_anomalies = self._collect_triggered_anomalies(anomalies, matched_triggers)

            metric_score, metric_evidence = self._metric_support(category, metrics)
            signal_score, signal_evidence = self._signal_support(category, signal_scores)

            if not matched_anomalies and signal_score > 0:
                matched_anomalies = self._collect_category_anomalies(anomalies, category)
            if not matched_anomalies:
                continue
            if not (matched_triggers or signal_score > 0 or metric_score > 0):
                continue
            # Avoid over-triggering secondary causes from weak fuzzy signals.
            if not matched_triggers and signal_score < 2.5 and metric_score < 1.0:
                continue

            matched_count = len(matched_triggers) if matched_triggers else 1
            total_count = len(triggers) if triggers else 1
            confidence = self._calculate_confidence(
                float(pattern.get("confidence_base", 0.7) or 0.7),
                matched_count,
                total_count,
                matched_anomalies,
                metric_score + signal_score * 0.25,
                critical_count=critical_count,
                high_count=high_count,
            )

            evidence = list(metric_evidence) + list(signal_evidence)
            for anomaly in matched_anomalies:
                if anomaly.evidence:
                    evidence.extend([str(item) for item in anomaly.evidence])
            evidence = list(dict.fromkeys([str(item).strip() for item in evidence if str(item).strip()]))

            related = list(dict.fromkeys([str(a.rule_name) for a in matched_anomalies]))[:6]
            if not related:
                related = matched_triggers[:6] or [category]

            root_causes.append(
                RootCause(
                    name=str(pattern.get("name", "待确认")),
                    confidence=confidence,
                    evidence=evidence[:5],
                    affected_scope=self._get_affected_scope(anomalies, metrics),
                    suggestions=list(pattern.get("suggestions", []) or []),
                    related_anomalies=related,
                )
            )

        root_causes.sort(key=lambda x: x.confidence, reverse=True)
        selected: List[RootCause] = []
        for rc in root_causes:
            rel = set([str(item).strip() for item in rc.related_anomalies if str(item).strip()])
            overlap_max = 0.0
            for prev in selected:
                prev_rel = set([str(item).strip() for item in prev.related_anomalies if str(item).strip()])
                union = rel | prev_rel
                if not union:
                    continue
                overlap = len(rel & prev_rel) / max(len(union), 1)
                overlap_max = max(overlap_max, overlap)
            if overlap_max >= 0.35:
                rc.confidence = round(max(0.40, rc.confidence * (1 - overlap_max * 0.28)), 2)
            selected.append(rc)

        root_causes.sort(key=lambda x: x.confidence, reverse=True)
        return root_causes[:3]

    def _calculate_confidence(
        self,
        base: float,
        matched: int,
        total: int,
        anomalies: List[Anomaly],
        metric_score: float,
        critical_count: int = 0,
        high_count: int = 0,
    ) -> float:
        match_ratio = matched / max(total, 1)
        confidence = float(base) * match_ratio

        if anomalies:
            sev_weight = sum(self._severity_score(a.severity) for a in anomalies) / max(len(anomalies), 1)
            confidence += min((sev_weight - 1.0) * 0.08, 0.22)

        confidence += min(metric_score * 0.06, 0.24)

        if critical_count > 0:
            confidence += 0.05
        elif high_count > 0:
            confidence += 0.03

        if any(a.severity == Severity.CRITICAL for a in anomalies):
            confidence += 0.04

        confidence = max(0.10, min(confidence, 0.95))
        return round(confidence, 2)

    @staticmethod
    def _get_affected_scope(anomalies: List[Anomaly], metrics: Dict[str, Any]) -> str:
        total_packets = int(metrics.get("basic", {}).get("total_packets", 0) or 0)
        affected_count = int(sum(int(getattr(a, "count", 0) or 0) for a in anomalies))

        if total_packets <= 0:
            return "未知"
        ratio = affected_count / max(total_packets, 1)
        if ratio > 0.5:
            return "全局影响"
        if ratio > 0.1:
            return "部分流量受影响"
        return "少量流量受影响"
