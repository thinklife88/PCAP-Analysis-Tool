"""AI analysis orchestrator and resilient response parser."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ai.client import AIClient
from ai.prompts import PromptBuilder
from utils.logger import setup_logger

logger = setup_logger()


@dataclass
class AIAnalysisResult:
    """Normalized AI analysis payload."""

    summary: str
    root_cause: str
    affected_systems: List[str]
    troubleshooting_steps: List[str]
    prevention: List[str]
    risk_level: str
    confidence: float
    raw_response: str


class AIAnalyzer:
    """AI analyzer wrapper with robust response parsing."""

    def __init__(self):
        self.client = AIClient()

    def analyze(
        self,
        metrics: Dict[str, Any],
        anomalies: List[Any],
        problem_flows: List[Dict[str, Any]],
        analysis_mode: str = "deep",
        local_result: Optional[Any] = None,
    ) -> Optional[AIAnalysisResult]:
        """Run AI analysis and parse the model response."""
        try:
            system_prompt = PromptBuilder.build_system_prompt(analysis_mode=analysis_mode)
            prompt = PromptBuilder.build_analysis_prompt(
                metrics,
                anomalies,
                problem_flows,
                analysis_mode=analysis_mode,
                local_result=local_result,
            )
            logger.info("Calling AI analyzer...")

            response = self.client.analyze(prompt, system_prompt=system_prompt)
            if not response:
                logger.error("AI returned empty response.")
                return None
            return self._parse_response(response)
        except Exception as exc:
            logger.error(f"AI analyze failed: {exc}")
            return None

    def _parse_response(self, response: str) -> AIAnalysisResult:
        """Parse AI output. Prefer JSON, then fallback to section parsing."""
        payload = self._extract_json_payload(response)
        if payload:
            return self._build_result_from_payload(payload, response)

        logger.warning("AI output is not valid JSON, fallback to text parser.")
        return self._parse_legacy_text(response)

    @staticmethod
    def _extract_json_payload(response: str) -> Optional[Dict[str, Any]]:
        text = str(response or "").strip()
        if not text:
            return None

        direct_obj = AIAnalyzer._try_json_object(text)
        if direct_obj is not None:
            return direct_obj

        # Strip markdown fences if model ignored instruction.
        fence_match = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
        if fence_match:
            fenced = fence_match.group(1).strip()
            fenced_obj = AIAnalyzer._try_json_object(fenced)
            if fenced_obj is not None:
                return fenced_obj

        # Try to recover the first balanced JSON object from mixed text.
        for candidate in AIAnalyzer._extract_balanced_json_objects(text):
            obj = AIAnalyzer._try_json_object(candidate)
            if obj is not None:
                return obj

        return None

    @staticmethod
    def _try_json_object(candidate: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(candidate)
        except Exception:
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _extract_balanced_json_objects(text: str) -> List[str]:
        candidates: List[str] = []
        depth = 0
        start_idx: Optional[int] = None
        in_string = False
        escaping = False

        for i, ch in enumerate(text):
            if in_string:
                if escaping:
                    escaping = False
                    continue
                if ch == "\\":
                    escaping = True
                    continue
                if ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
                continue

            if ch == "{":
                if depth == 0:
                    start_idx = i
                depth += 1
                continue

            if ch == "}":
                if depth <= 0:
                    continue
                depth -= 1
                if depth == 0 and start_idx is not None:
                    candidates.append(text[start_idx : i + 1])
                    start_idx = None

        return candidates

    def _build_result_from_payload(self, payload: Dict[str, Any], raw: str) -> AIAnalysisResult:
        summary = self._clean_text(payload.get("summary"), "AI分析完成")
        root_cause = self._clean_text(payload.get("root_cause"), "")
        affected_systems = self._normalize_list(payload.get("affected_systems"))
        troubleshooting_steps = self._normalize_list(payload.get("troubleshooting_steps"))
        prevention = self._normalize_list(payload.get("prevention"))
        risk_level = self._normalize_risk_level(payload.get("risk_level"))
        confidence = self._normalize_confidence(payload.get("confidence"))

        if not root_cause and summary:
            root_cause = summary

        return AIAnalysisResult(
            summary=summary,
            root_cause=root_cause,
            affected_systems=affected_systems,
            troubleshooting_steps=troubleshooting_steps,
            prevention=prevention,
            risk_level=risk_level,
            confidence=confidence,
            raw_response=raw,
        )

    def _parse_legacy_text(self, response: str) -> AIAnalysisResult:
        lines = [line.strip() for line in str(response or "").splitlines()]
        summary = ""
        root_cause_lines: List[str] = []
        affected_systems: List[str] = []
        troubleshooting_steps: List[str] = []
        prevention: List[str] = []
        risk_level = "中"
        confidence = 0.8

        section = ""
        for line in lines:
            if not line:
                continue

            lower = line.lower()
            if any(k in line for k in ["核心问题", "问题概述", "summary"]):
                section = "summary"
                continue
            if any(k in line for k in ["根本原因", "根因", "root cause"]):
                section = "root_cause"
                continue
            if any(k in line for k in ["受影响", "影响系统", "affected"]):
                section = "affected"
                continue
            if any(k in line for k in ["排查步骤", "处置步骤", "troubleshooting", "steps"]):
                section = "steps"
                continue
            if any(k in line for k in ["预防措施", "预防建议", "prevention"]):
                section = "prevention"
                continue
            if any(k in line for k in ["风险", "risk"]):
                section = "risk"
                # The same line may contain value, so continue parsing below.

            if section == "summary":
                if not summary and not line.startswith("#"):
                    summary = self._strip_prefix(line)
                continue

            if section == "root_cause":
                if not line.startswith("#"):
                    root_cause_lines.append(self._strip_prefix(line))
                continue

            if section == "affected" and self._is_list_item(line):
                affected_systems.append(self._strip_prefix(line))
                continue

            if section == "steps" and self._is_list_item(line):
                troubleshooting_steps.append(self._strip_prefix(line))
                continue

            if section == "prevention" and self._is_list_item(line):
                prevention.append(self._strip_prefix(line))
                continue

            if section == "risk":
                risk_level = self._normalize_risk_level(line)
                maybe_conf = self._normalize_confidence(line)
                confidence = maybe_conf if maybe_conf > 0 else confidence
                continue

            # Key-value fallback even if section title is missing.
            if ":" in line or "：" in line:
                key, value = re.split(r"[:：]", line, maxsplit=1)
                key_lower = key.strip().lower()
                value = value.strip()
                if key_lower in {"risk_level", "risk", "风险等级", "风险"}:
                    risk_level = self._normalize_risk_level(value)
                elif key_lower in {"confidence", "置信度"}:
                    confidence = self._normalize_confidence(value)
                elif key_lower in {"summary", "核心问题"} and not summary:
                    summary = value
                elif key_lower in {"root_cause", "根因", "根本原因"}:
                    root_cause_lines.append(value)

        result = AIAnalysisResult(
            summary=summary or "AI分析完成",
            root_cause="\n".join([item for item in root_cause_lines if item]).strip() or summary or "",
            affected_systems=self._dedupe_preserve_order(affected_systems),
            troubleshooting_steps=self._dedupe_preserve_order(troubleshooting_steps),
            prevention=self._dedupe_preserve_order(prevention),
            risk_level=risk_level,
            confidence=confidence,
            raw_response=response,
        )
        return result

    @staticmethod
    def _clean_text(value: Any, fallback: str = "") -> str:
        text = str(value or "").strip()
        return text or fallback

    @staticmethod
    def _normalize_list(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            items = [item.strip() for item in re.split(r"[\n;；]", value) if item.strip()]
            return AIAnalyzer._dedupe_preserve_order([AIAnalyzer._strip_prefix(item) for item in items])
        if isinstance(value, list):
            items = [AIAnalyzer._strip_prefix(str(item).strip()) for item in value if str(item).strip()]
            return AIAnalyzer._dedupe_preserve_order(items)
        return [str(value).strip()] if str(value).strip() else []

    @staticmethod
    def _normalize_risk_level(value: Any) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return "中"
        if any(k in text for k in ["critical", "high", "严重", "高"]):
            return "高"
        if any(k in text for k in ["low", "minor", "轻", "低"]):
            return "低"
        if any(k in text for k in ["medium", "normal", "中"]):
            return "中"
        return "中"

    @staticmethod
    def _normalize_confidence(value: Any) -> float:
        if value is None:
            return 0.8

        if isinstance(value, (int, float)):
            val = float(value)
            if val > 1:
                val /= 100.0
            return max(0.0, min(val, 1.0))

        text = str(value).strip()
        if not text:
            return 0.8

        match = re.search(r"(-?\d+(?:\.\d+)?)\s*%?", text)
        if not match:
            return 0.8

        val = float(match.group(1))
        if "%" in text or val > 1:
            val /= 100.0
        return max(0.0, min(val, 1.0))

    @staticmethod
    def _is_list_item(text: str) -> bool:
        stripped = str(text).strip()
        if not stripped:
            return False
        if stripped.startswith(("-", "*", "•")):
            return True
        return re.match(r"^\d+[\.\)]\s*", stripped) is not None

    @staticmethod
    def _strip_prefix(text: str) -> str:
        stripped = str(text or "").strip()
        stripped = re.sub(r"^[-*•]\s*", "", stripped)
        stripped = re.sub(r"^\d+[\.\)]\s*", "", stripped)
        return stripped.strip()

    @staticmethod
    def _dedupe_preserve_order(items: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for item in items:
            key = item.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(key)
        return out
