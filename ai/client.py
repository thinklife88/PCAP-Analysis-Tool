"""Unified AI client wrapper."""

from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

from utils.config import get_config
from utils.logger import setup_logger

logger = setup_logger()


class AIClient:
    """Unified AI client with multi-provider compatibility."""

    OPENAI_COMPATIBLE_PROVIDERS = {
        "openai",
        "qwen",
        "deepseek",
        "siliconflow",
        "ollama",
        "minimax",
        "kimi",
        "custom",
    }

    def __init__(self):
        self.config = get_config()
        self.provider = self.config.get("ai_analysis.provider", "openai")
        self.api_base = self.config.get("ai_analysis.api_base", "")
        self.api_key = self.config.get("ai_analysis.api_key", "")
        self.model = self.config.get("ai_analysis.model", "gpt-5")
        self.temperature = self.config.get("ai_analysis.temperature", 0.3)
        self.max_tokens = self.config.get("ai_analysis.max_tokens", 4096)
        self.request_timeout = int(self.config.get("ai_analysis.request_timeout_seconds", 90))

    @staticmethod
    def _response_snippet(response: requests.Response, limit: int = 300) -> str:
        try:
            text = response.text.strip().replace("\n", " ")
        except Exception:
            text = "<no-body>"
        if not text:
            text = "<empty-body>"
        if len(text) > limit:
            return f"{text[:limit]}..."
        return text

    def _log_http_error(self, action: str, response: requests.Response):
        snippet = self._response_snippet(response)
        content_type = response.headers.get("Content-Type", "<unknown>")
        logger.error(
            f"{action} failed: status={response.status_code}, content-type={content_type}, body={snippet}"
        )

    def _safe_json(self, response: requests.Response, action: str) -> Optional[Dict[str, Any]]:
        try:
            payload = response.json()
        except ValueError:
            content_type = response.headers.get("Content-Type", "<unknown>")
            snippet = self._response_snippet(response)
            logger.error(
                f"{action} returned non-JSON response: status={response.status_code}, "
                f"content-type={content_type}, body={snippet}"
            )
            return None

        if not isinstance(payload, dict):
            logger.error(f"{action} returned unexpected JSON type: {type(payload).__name__}")
            return None
        return payload

    def _openai_candidate_bases(self) -> List[str]:
        base = self.api_base.rstrip("/")
        if not base:
            return []

        candidates: List[str] = [base]

        try:
            parsed = urlsplit(base)
            path = parsed.path or ""
        except Exception:
            path = ""

        # Standard OpenAI-compatible base.
        if not path.endswith("/v1") and "/v1/" not in path:
            candidates.append(f"{base}/v1")

        # If user configured nested path like .../v1/responses, also try trimmed .../v1.
        if "/v1/" in path:
            prefix = path.split("/v1/", 1)[0]
            normalized_path = f"{prefix}/v1"
            try:
                parsed = urlsplit(base)
                trimmed_base = urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", ""))
            except Exception:
                trimmed_base = ""
            if trimmed_base:
                candidates.append(trimmed_base.rstrip("/"))

        unique: List[str] = []
        for item in candidates:
            text = str(item or "").strip().rstrip("/")
            if text and text not in unique:
                unique.append(text)
        return unique

    def _openai_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    @staticmethod
    def _extract_openai_message(payload: Dict[str, Any]) -> Optional[str]:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            return None

        first = choices[0] or {}
        if not isinstance(first, dict):
            return None

        message = first.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                parts = []
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        if isinstance(text, str) and text:
                            parts.append(text)
                if parts:
                    return "\n".join(parts)

        text = first.get("text")
        if isinstance(text, str):
            return text
        return None

    def test_connection(self) -> bool:
        """Test provider connectivity with real checks."""
        try:
            if self.provider in self.OPENAI_COMPATIBLE_PROVIDERS:
                return self._test_openai_compatible()
            if self.provider == "anthropic":
                return self._test_anthropic()
            if self.provider == "gemini":
                return self._test_gemini()
            if self.provider == "glm":
                return self._test_glm()
            return False
        except Exception as exc:
            logger.error(f"API connectivity test failed: {exc}")
            return False

    def _test_openai_compatible(self) -> bool:
        if not self.api_base:
            return False

        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

        for base in self._openai_candidate_bases():
            try:
                response = requests.get(f"{base}/models", headers=headers, timeout=10)
            except requests.RequestException as exc:
                logger.error(f"OpenAI-compatible model probe failed at {base}: {exc}")
                continue

            if response.status_code == 200:
                payload = self._safe_json(response, f"OpenAI-compatible /models probe ({base})")
                if payload and isinstance(payload.get("data"), list):
                    return True
                logger.warning(f"OpenAI-compatible /models probe ({base}) returned unexpected payload.")
                if self._probe_openai_chat(base):
                    return True
                continue

            if response.status_code in (401, 403):
                self._log_http_error(f"OpenAI-compatible /models auth ({base})", response)
                return False

            if response.status_code == 404:
                if self._probe_openai_chat(base):
                    return True
                continue

            self._log_http_error(f"OpenAI-compatible /models probe ({base})", response)

        return False

    def _probe_openai_chat(self, base: str) -> bool:
        """Fallback check for providers without /models endpoint."""
        if not base:
            return False

        url = f"{base}/chat/completions"
        headers = self._openai_headers()

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": "ping"}],
            "temperature": 0,
            "max_tokens": 1,
        }
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=min(self.request_timeout, 30))
            if response.status_code != 200:
                self._log_http_error(f"OpenAI-compatible chat probe ({base})", response)
                return False

            response_payload = self._safe_json(response, f"OpenAI-compatible chat probe ({base})")
            if not response_payload:
                return False

            if response_payload.get("error"):
                logger.error(
                    f"OpenAI-compatible chat probe ({base}) returned error payload: {response_payload.get('error')}"
                )
                return False

            return bool(self._extract_openai_message(response_payload))
        except requests.RequestException as exc:
            logger.error(f"OpenAI-compatible chat probe failed at {base}: {exc}")
            return False

    def _test_anthropic(self) -> bool:
        if not self.api_base or not self.api_key:
            return False
        url = f"{self.api_base.rstrip('/')}/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        data = {
            "model": self.model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "ping"}],
        }
        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return True
        self._log_http_error("Anthropic probe", response)
        return False

    def _test_gemini(self) -> bool:
        if not self.api_base or not self.api_key:
            return False
        url = f"{self.api_base.rstrip('/')}/models/{self.model}:generateContent?key={self.api_key}"
        data = {"contents": [{"parts": [{"text": "ping"}]}]}
        response = requests.post(url, json=data, timeout=10)
        if response.status_code == 200:
            return True
        self._log_http_error("Gemini probe", response)
        return False

    def _test_glm(self) -> bool:
        if not self.api_base or not self.api_key:
            return False
        url = f"{self.api_base.rstrip('/')}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
        }
        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return True
        self._log_http_error("GLM probe", response)
        return False

    @staticmethod
    def _build_openai_messages(prompt: str, system_prompt: Optional[str] = None) -> List[Dict[str, str]]:
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": str(system_prompt)})
        messages.append({"role": "user", "content": str(prompt)})
        return messages

    def analyze(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """Call AI model for analysis content."""
        try:
            if self.provider in self.OPENAI_COMPATIBLE_PROVIDERS:
                return self._call_openai_compatible(prompt, system_prompt=system_prompt)
            if self.provider == "anthropic":
                return self._call_anthropic(prompt, system_prompt=system_prompt)
            if self.provider == "gemini":
                return self._call_gemini(prompt, system_prompt=system_prompt)
            if self.provider == "glm":
                return self._call_glm(prompt, system_prompt=system_prompt)
            return None
        except Exception as exc:
            logger.error(f"AI request failed: {exc}")
            return None

    def _call_openai_compatible(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        if not self.api_base:
            return None

        headers = self._openai_headers()
        base_data = {
            "model": self.model,
            "messages": self._build_openai_messages(prompt, system_prompt=system_prompt),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        for base in self._openai_candidate_bases():
            url = f"{base}/chat/completions"
            retry_prompt = self._condense_prompt_for_retry(prompt)
            for attempt in range(2):
                data = dict(base_data)
                timeout = self.request_timeout
                if attempt == 1:
                    data["messages"] = self._build_openai_messages(retry_prompt, system_prompt=system_prompt)
                    data["max_tokens"] = min(int(self.max_tokens), 1200)
                    data["temperature"] = min(float(self.temperature), 0.2)
                    timeout = max(self.request_timeout, 120)

                payload_variants: List[Dict[str, Any]] = []
                if attempt == 0:
                    json_data = dict(data)
                    json_data["response_format"] = {"type": "json_object"}
                    payload_variants.append(json_data)
                payload_variants.append(data)

                for variant in payload_variants:
                    uses_json_format = "response_format" in variant
                    try:
                        response = requests.post(url, headers=headers, json=variant, timeout=timeout)
                    except requests.Timeout as exc:
                        logger.error(
                            f"OpenAI-compatible analyze timeout at {base}: attempt={attempt + 1}, timeout={timeout}s, error={exc}"
                        )
                        continue
                    except requests.RequestException as exc:
                        logger.error(f"OpenAI-compatible analyze failed at {base}: {exc}")
                        continue

                    if response.status_code != 200:
                        if uses_json_format and response.status_code in (400, 422):
                            snippet = self._response_snippet(response).lower()
                            if any(
                                key in snippet
                                for key in ("response_format", "json_object", "json schema", "unsupported", "invalid")
                            ):
                                logger.warning(
                                    f"Provider at {base} rejected response_format json_object, fallback to plain JSON instruction."
                                )
                                continue
                        self._log_http_error(f"OpenAI-compatible analyze ({base})", response)
                        if response.status_code in (408, 429, 500, 502, 503, 504):
                            continue
                        break

                    payload = self._safe_json(response, f"OpenAI-compatible analyze ({base})")
                    if not payload:
                        continue

                    if payload.get("error"):
                        if uses_json_format:
                            err_text = str(payload.get("error", "")).lower()
                            if any(
                                key in err_text
                                for key in ("response_format", "json_object", "json schema", "unsupported", "invalid")
                            ):
                                logger.warning(
                                    f"Provider at {base} returned response_format error payload, fallback to plain JSON instruction."
                                )
                                continue
                        logger.error(f"OpenAI-compatible analyze ({base}) returned error payload: {payload.get('error')}")
                        continue

                    content = self._extract_openai_message(payload)
                    if content and content.strip():
                        return content

                    logger.error(f"OpenAI-compatible analyze ({base}) returned empty content payload.")
                    continue

        return None

    @staticmethod
    def _condense_prompt_for_retry(prompt: str, keep: int = 6000) -> str:
        text = (prompt or "").strip()
        if len(text) <= keep:
            return text
        head = keep // 2
        tail = keep - head
        return (
            text[:head]
            + "\n\n[内容过长，以下省略部分中间内容，仅保留关键头尾用于快速诊断]\n\n"
            + text[-tail:]
        )

    def _call_gemini(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        if not self.api_base or not self.api_key:
            return None
        url = f"{self.api_base.rstrip('/')}/models/{self.model}:generateContent?key={self.api_key}"
        merged_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        data = {"contents": [{"parts": [{"text": merged_prompt}]}]}

        response = requests.post(url, json=data, timeout=self.request_timeout)
        if response.status_code == 200:
            payload = self._safe_json(response, "Gemini analyze")
            if not payload:
                return None
            candidates = payload.get("candidates") or []
            if candidates and candidates[0].get("content", {}).get("parts"):
                return candidates[0]["content"]["parts"][0].get("text")
            logger.error("Gemini analyze returned empty candidates payload.")
            return None
        self._log_http_error("Gemini analyze", response)
        return None

    def _call_glm(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        if not self.api_base or not self.api_key:
            return None
        url = f"{self.api_base.rstrip('/')}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        data = {"model": self.model, "messages": self._build_openai_messages(prompt, system_prompt=system_prompt)}

        response = requests.post(url, headers=headers, json=data, timeout=self.request_timeout)
        if response.status_code == 200:
            payload = self._safe_json(response, "GLM analyze")
            if not payload:
                return None
            return self._extract_openai_message(payload)
        self._log_http_error("GLM analyze", response)
        return None

    def _call_anthropic(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        if not self.api_base or not self.api_key:
            return None
        url = f"{self.api_base.rstrip('/')}/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        data = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            data["system"] = str(system_prompt)

        response = requests.post(url, headers=headers, json=data, timeout=self.request_timeout)
        if response.status_code == 200:
            payload = self._safe_json(response, "Anthropic analyze")
            if not payload:
                return None
            content = payload.get("content") or []
            if content and isinstance(content[0], dict):
                return content[0].get("text")
            logger.error("Anthropic analyze returned empty content payload.")
            return None
        self._log_http_error("Anthropic analyze", response)
        return None
