"""AI analysis prompt templates."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


class PromptBuilder:
    """Prompt builder."""

    MAX_ANOMALIES_IN_PROMPT = 25
    MAX_FLOWS_IN_PROMPT = 10
    MAX_TEXT_FIELD_LENGTH = 220

    @staticmethod
    def build_system_prompt(analysis_mode: str = "deep") -> str:
        """Build compact system prompt for stable JSON output."""
        mode_key = str(analysis_mode or "deep").lower()
        mode_label, mode_goal, mode_focus, min_steps = PromptBuilder._mode_profile(mode_key)
        return (
            "你是资深网络故障诊断工程师。"
            "你必须基于输入证据作答，不得臆测。"
            "若证据不足，明确写出“不确定点”和“补充抓取建议”。"
            "输出语言为中文，语气专业、简洁、可执行。"
            "必须只输出一个JSON对象，不得输出Markdown、解释文字或代码块。"
            f"当前模式={mode_label}；模式目标={mode_goal}；模式重点={mode_focus}；"
            f"troubleshooting_steps 至少 {min_steps} 步。"
        )

    @staticmethod
    def build_analysis_prompt(
        metrics: Dict[str, Any],
        anomalies: List[Any],
        problem_flows: List[Dict[str, Any]],
        analysis_mode: str = "deep",
        local_result: Optional[Any] = None,
    ) -> str:
        """Build analysis prompt with mode-aware evidence pack."""
        mode_key = str(analysis_mode or metrics.get("analysis_mode") or "deep").lower()
        mode_label, mode_goal, mode_focus, min_steps = PromptBuilder._mode_profile(mode_key)

        basic = metrics.get("basic", {}) or {}
        protocol = metrics.get("protocol", {}) or {}
        tcp = metrics.get("tcp", {}) or {}
        network = metrics.get("network", {}) or {}
        app = metrics.get("application", {}) or {}
        scope = metrics.get("analysis_scope", {}) or {}
        thresholds = metrics.get("config_thresholds", {}) or {}

        anomalies_text = PromptBuilder._build_anomalies_text(anomalies)
        flows_text = PromptBuilder._build_problem_flows_text(problem_flows)
        local_snapshot = PromptBuilder._build_local_snapshot(local_result)

        prompt = f"""# 任务
请根据以下“规则引擎与统计证据包”，给出可执行网络故障分析结果。

## 模式信息
- mode_key: {mode_key}
- 模式: {mode_label}
- 模式目标: {mode_goal}
- 输出重点: {mode_focus}

## 抓包范围与样本质量
- 分析范围: {scope.get('description', 'all traffic')}
- 过滤模式: {scope.get('mode', 'all')}
- 输入包数: {scope.get('input_packets', basic.get('total_packets', 0))}
- 命中包数: {scope.get('matched_packets', basic.get('total_packets', 0))}
- 采样方式: {scope.get('sampling_mode', 'full')}
- 采样可信度: {scope.get('sampling_confidence', 'high')}
- 包数上限触发: {scope.get('limit_hit', False)}
- 超时触发: {scope.get('timeout_hit', False)}

## 基础统计
- 总数据包数: {basic.get('total_packets', 0)}
- 分析时长: {basic.get('duration', 0):.2f} 秒
- 总字节数: {basic.get('total_bytes', 0)}

## 协议分布
{PromptBuilder._format_dict(protocol)}

## 关键TCP/网络/应用指标
- TCP总包: {tcp.get('total_tcp', tcp.get('total', 0))}
- SYN: {tcp.get('syn', 0)}
- RST: {tcp.get('rst', 0)}
- 重传率: {float(tcp.get('retrans_rate', 0) or 0) * 100:.2f}%
- 平均RTT: {float(tcp.get('avg_rtt', 0) or 0) * 1000:.2f} ms
- RTT样本数: {tcp.get('rtt_samples', 0)}
- 流量不对称比: {network.get('asymmetry_ratio', 0)}
- DNS失败数: {app.get('dns_error_rcode', 0)}
- HTTP错误数: {app.get('http_error_responses', 0)}

## 阈值参考
{PromptBuilder._format_thresholds(thresholds)}

## 本地引擎初判（可用于交叉验证）
{local_snapshot}

## 检测到的异常（按规则）
{anomalies_text}

## 问题流详情（端点级）
{flows_text}

## 输出契约（必须严格遵守）
你必须只输出一个 JSON 对象，字段如下：
{{
  "summary": "一句话核心结论（必须点名关键端点/IP:port）",
  "root_cause": "根因分析（需明确证据链，不少于2条证据）",
  "affected_systems": ["受影响端点或服务1", "受影响端点或服务2"],
  "troubleshooting_steps": ["步骤1（含命令或操作）", "步骤2", "步骤3"],
  "prevention": ["预防建议1", "预防建议2", "预防建议3"],
  "risk_level": "高/中/低",
  "confidence": 0.0
}}

## 强约束
1. 不得输出 JSON 之外的任何文字。
2. troubleshooting_steps 至少 {min_steps} 步，必须可执行。
3. 必须引用输入证据进行推理；若证据不足，要在 root_cause 中明确“不确定点”。
4. confidence 必须为 0~1 数值，且与证据充分性一致。
5. 若本地引擎初判与证据冲突，你应指出冲突并给出更可信结论。
"""
        return prompt

    @staticmethod
    def _mode_profile(mode_key: str) -> Tuple[str, str, str, int]:
        if mode_key == "quick":
            return (
                "快速分析（应急级）",
                "在有限样本内快速定位故障点并给出止血动作",
                "强调关键端点、故障类型、短路径处置",
                3,
            )
        if mode_key == "diagnosis":
            return (
                "故障诊断（工单级）",
                "形成可直接落地的排障步骤与验收闭环",
                "强调责任域、排查顺序、修复优先级",
                5,
            )
        return (
            "深度分析（诊断级）",
            "完成跨层证据链的定位与原因确认",
            "强调根因收敛与回归验证",
            4,
        )

    @staticmethod
    def _build_local_snapshot(local_result: Optional[Any]) -> str:
        if local_result is None:
            return "- 无本地引擎结论"
        summary = PromptBuilder._short_text(getattr(local_result, "summary", ""), 160)
        root_cause = PromptBuilder._short_text(getattr(local_result, "root_cause", ""), 220)
        risk = str(getattr(local_result, "risk_level", "") or "-")
        conf = float(getattr(local_result, "confidence", 0.0) or 0.0)
        return (
            f"- summary: {summary or '-'}\n"
            f"- root_cause: {root_cause or '-'}\n"
            f"- risk_level: {risk}\n"
            f"- confidence: {conf:.2f}"
        )

    @staticmethod
    def _build_anomalies_text(anomalies: List[Any]) -> str:
        if not anomalies:
            return "- 未检测到异常"

        limited = anomalies[: PromptBuilder.MAX_ANOMALIES_IN_PROMPT]
        rows: List[str] = []
        for i, anomaly in enumerate(limited, 1):
            severity = str(getattr(getattr(anomaly, "severity", None), "value", "unknown"))
            rule_name = str(getattr(anomaly, "rule_name", "unknown_rule"))
            description = PromptBuilder._short_text(getattr(anomaly, "description", ""))
            count = int(getattr(anomaly, "count", 0) or 0)
            evidence = getattr(anomaly, "evidence", []) or []
            ev_head = PromptBuilder._short_text(evidence[0], 120) if evidence else "-"

            rows.append(f"{i}. {rule_name} [{severity}]")
            rows.append(f"   count: {count}")
            rows.append(f"   描述: {description}")
            rows.append(f"   证据样本: {ev_head}")

        omitted = max(0, len(anomalies) - len(limited))
        if omitted:
            rows.append(f"... 其余异常 {omitted} 条已省略（完整内容见本地报告）")
        return "\n".join(rows)

    @staticmethod
    def _build_problem_flows_text(problem_flows: List[Dict[str, Any]]) -> str:
        if not problem_flows:
            return "- 未识别出问题流"

        limited = problem_flows[: PromptBuilder.MAX_FLOWS_IN_PROMPT]
        rows: List[str] = []

        for i, flow in enumerate(limited, 1):
            src_ip = flow.get("src_ip", "?")
            src_port = flow.get("src_port", "?")
            dst_ip = flow.get("dst_ip", "?")
            dst_port = flow.get("dst_port", "?")
            issues = [PromptBuilder._short_text(item, 96) for item in (flow.get("issues") or [])]

            retrans_rate = float(flow.get("retrans_rate", 0.0) or 0.0)
            packet_count = int(flow.get("packet_count", 0) or 0)
            rst_count = int(flow.get("rst_count", 0) or 0)
            syn_count = int(flow.get("syn_count", 0) or 0)
            avg_rtt = float(flow.get("avg_rtt", 0.0) or 0.0) * 1000
            max_gap = float(flow.get("max_gap", 0.0) or 0.0)

            rows.append(f"{i}. {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            rows.append(f"   问题: {', '.join(issues) if issues else '-'}")
            rows.append(
                "   包数: {packet_count}, SYN: {syn_count}, RST: {rst_count}, 重传率: {retrans:.2f}%, 平均RTT: {rtt:.2f}ms, 最大间隔: {max_gap:.2f}s".format(
                    packet_count=packet_count,
                    syn_count=syn_count,
                    rst_count=rst_count,
                    retrans=retrans_rate * 100.0,
                    rtt=avg_rtt,
                    max_gap=max_gap,
                )
            )

        omitted = max(0, len(problem_flows) - len(limited))
        if omitted:
            rows.append(f"... 其余问题流 {omitted} 条已省略")
        return "\n".join(rows)

    @staticmethod
    def _format_dict(d: Dict[str, Any]) -> str:
        if not d:
            return "- 无"
        rows: List[str] = []
        for key, value in d.items():
            rows.append(f"- {key}: {value}")
        return "\n".join(rows)

    @staticmethod
    def _format_thresholds(d: Dict[str, Any]) -> str:
        if not d:
            return "- 使用默认阈值（未显式配置）"
        keys = [
            "retransmission_rate",
            "rst_rate",
            "rtt_high_ms",
            "dns_failure_rate",
            "http_error_rate",
            "asymmetry_ratio",
            "max_interval_s",
        ]
        rows: List[str] = []
        for k in keys:
            if k in d:
                rows.append(f"- {k}: {d.get(k)}")
        if not rows:
            return "- 阈值存在，但未命中常用核心项"
        return "\n".join(rows)

    @staticmethod
    def _short_text(value: Any, max_len: int = MAX_TEXT_FIELD_LENGTH) -> str:
        text = str(value or "").strip().replace("\n", " ")
        if len(text) <= max_len:
            return text
        return f"{text[:max_len]}..."
