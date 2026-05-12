"""故障检测引擎"""
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from collections import Counter
from utils.logger import setup_logger

logger = setup_logger()

class Severity(str, Enum):
    LOW = "低"
    MEDIUM = "中"
    HIGH = "高"
    CRITICAL = "严重"

@dataclass
class Anomaly:
    """异常事件"""
    rule_name: str
    severity: Severity
    description: str
    evidence: List[str]
    affected_flows: List[str]
    count: int

class DetectionEngine:
    def __init__(self):
        self.rules = []
        self.anomalies: List[Anomaly] = []

    @staticmethod
    def _severity_score(level: Severity) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }.get(level, 0)

    def register_rule(self, rule):
        """注册检测规则"""
        self.rules.append(rule)

    @staticmethod
    def _normalize_scope_token(text: str) -> str:
        value = str(text or "").strip().lower()
        if not value:
            return ""
        return "".join(ch for ch in value if ch.isalnum() or ch in {".", ":", "-", ">", "_"})

    @classmethod
    def _affected_scope_key(cls, anomaly: Anomaly) -> str:
        flows = [cls._normalize_scope_token(item) for item in (anomaly.affected_flows or []) if str(item).strip()]
        flows = sorted(set([item for item in flows if item]))
        if flows:
            return "|".join(flows[:3])

        evidence_lines = [cls._normalize_scope_token(item) for item in (anomaly.evidence or []) if str(item).strip()]
        for line in evidence_lines:
            if "->" in line or ":" in line:
                return line[:120]

        desc = cls._normalize_scope_token(getattr(anomaly, "description", ""))
        return desc[:80] if desc else "global"

    @classmethod
    def _anomaly_dedupe_key(cls, anomaly: Anomaly) -> Tuple[str, str]:
        rule = str(getattr(anomaly, "rule_name", "") or "").strip().lower()
        return rule, cls._affected_scope_key(anomaly)

    def _deduplicate_anomalies(self, anomalies: List[Anomaly]) -> List[Anomaly]:
        merged: Dict[Tuple[str, str], Anomaly] = {}
        for item in anomalies:
            key = self._anomaly_dedupe_key(item)
            if key not in merged:
                merged[key] = Anomaly(
                    rule_name=item.rule_name,
                    severity=item.severity,
                    description=item.description,
                    evidence=list(item.evidence or []),
                    affected_flows=list(item.affected_flows or []),
                    count=int(item.count or 0),
                )
                continue

            current = merged[key]
            if self._severity_score(item.severity) > self._severity_score(current.severity):
                current.severity = item.severity
                current.description = item.description

            current.count += int(item.count or 0)
            current.evidence = list(dict.fromkeys((current.evidence or []) + (item.evidence or [])))[:40]
            current.affected_flows = list(
                dict.fromkeys((current.affected_flows or []) + (item.affected_flows or []))
            )[:100]

        return list(merged.values())

    def _build_correlation_anomaly(self, anomalies: List[Anomaly], metrics: Dict[str, Any]) -> Optional[Anomaly]:
        if not anomalies:
            return None

        names = [a.rule_name for a in anomalies]
        has_connect_fail = any("连接失败" in n or "握手失败" in n for n in names)
        has_intercept = any("拦截" in n or "重置" in n for n in names)
        has_loss = any(("重传" in n) or ("丢包" in n) for n in names)
        has_latency = any(("延迟" in n) or ("卡慢" in n) for n in names)
        has_receiver_bottleneck = any("零窗口" in n for n in names)
        has_multi_layer = any("跨层级" in n for n in names)
        has_pmtu = any(("PMTU" in n) or ("分片" in n) or ("长度异常" in n) for n in names)
        has_syn_retry = any("SYN重试" in n for n in names)

        diagnosis = ""
        severity = Severity.HIGH
        if has_pmtu and has_loss:
            diagnosis = "高置信：路径MTU/分片链路异常导致数据面重传，优先排查PMTUD与MSS配置"
            severity = Severity.CRITICAL
        elif has_syn_retry and (has_connect_fail or has_intercept):
            diagnosis = "高置信：连接建立阶段存在SYN重试压力，疑似服务不可达或接入策略丢弃"
            severity = Severity.CRITICAL
        elif has_connect_fail and has_intercept:
            diagnosis = "高置信：连接建立阶段即被策略或服务端拒绝，故障位于L3/L4接入面"
            severity = Severity.CRITICAL
        elif has_receiver_bottleneck and (has_loss or has_latency):
            diagnosis = "高置信：接收端处理瓶颈导致传输抖动，优先排查主机资源与应用消费能力"
            severity = Severity.HIGH
        elif has_loss and has_latency:
            diagnosis = "高置信：链路质量劣化导致重传与时延同时升高，优先排查丢包和队列拥塞"
            severity = Severity.HIGH
        elif has_multi_layer:
            diagnosis = "检测到跨层级告警共振，建议按L3->L4->L7顺序执行分层排障"
            severity = Severity.HIGH
        else:
            return None

        flows = metrics.get("problem_flows", []) or []
        endpoint_counter = Counter(
            f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)}" for flow in flows
        )
        top_endpoints = endpoint_counter.most_common(3)
        endpoint_text = "；".join([f"{ep}({cnt}条)" for ep, cnt in top_endpoints]) if top_endpoints else "未知"

        evidence = [
            "相关异常: " + "；".join(names[:8]),
            f"热点端点: {endpoint_text}",
            "建议顺序: 先定位热点端点 -> 再执行命令清单 -> 最后做回归闭环",
        ]
        affected = []
        for flow in flows[:12]:
            affected.append(
                f"{flow.get('src_ip', 'unknown')}:{flow.get('src_port', 0)}->"
                f"{flow.get('dst_ip', 'unknown')}:{flow.get('dst_port', 0)}"
            )
        return Anomaly(
            rule_name="智能关联结论",
            severity=severity,
            description=diagnosis,
            evidence=evidence,
            affected_flows=affected,
            count=len(affected) if affected else len(anomalies),
        )

    def detect(self, metrics: Dict[str, Any]) -> List[Anomaly]:
        """执行所有检测规则"""
        self.anomalies = []

        for rule in self.rules:
            try:
                result = rule.check(metrics)
                if result:
                    self.anomalies.append(result)
            except Exception as e:
                logger.warning(f"Rule execution failed: {rule.__class__.__name__}: {e}")
                continue

        self.anomalies = self._deduplicate_anomalies(self.anomalies)
        correlation = self._build_correlation_anomaly(self.anomalies, metrics)
        if correlation and all(correlation.rule_name != a.rule_name for a in self.anomalies):
            self.anomalies.append(correlation)

        self.anomalies.sort(
            key=lambda x: (self._severity_score(getattr(x, "severity", Severity.LOW)), int(getattr(x, "count", 0))),
            reverse=True,
        )
        return self.anomalies
