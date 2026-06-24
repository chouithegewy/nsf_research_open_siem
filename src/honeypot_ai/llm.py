"""LLM client for local Ollama, LM Studio, or Open WebUI instances.

Supports:
1. OpenAI-compatible API (e.g. LM Studio, Ollama OpenAI compat) at /v1
2. Open WebUI API at /api
3. Ollama native API at /api/chat
"""
from __future__ import annotations

import json
import logging
import os
import textwrap
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Sequence

logger = logging.getLogger(__name__)

_DEFAULT_ENDPOINT = "http://localhost:11434"
_DEFAULT_TIMEOUT = 60

_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a senior SOC analyst reviewing eBPF telemetry from a honeypot.
    Given a batch of security events in JSON, produce a concise threat summary:
    1. Classify the activity (reconnaissance, exploitation, persistence, etc.)
    2. Identify MITRE ATT&CK techniques if recognizable.
    3. Highlight high-severity events and suspicious patterns.
    4. Provide a risk assessment (low / medium / high / critical).
    Keep the summary under 300 words.  Be precise and actionable.
""")


@dataclass
class LLMConfig:
    """Runtime configuration for the LLM client."""
    endpoint: str = field(default_factory=lambda: os.getenv("LLM_ENDPOINT", _DEFAULT_ENDPOINT))
    api_key: str = field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))
    model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", ""))
    enabled: bool = field(default_factory=lambda: os.getenv("LLM_ENABLED", "false").lower() == "true")
    timeout: int = field(default_factory=lambda: int(os.getenv("LLM_TIMEOUT", str(_DEFAULT_TIMEOUT))))


class LLMClient:
    """Lightweight client that talks to Ollama, LM Studio, or Open WebUI."""

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig()
        self.api_type = "openai"  # "openai", "open_webui", "ollama"

    def is_enabled(self) -> bool:
        if not self.config.enabled:
            return False
        endpoint = self.config.endpoint.lower()
        if "localhost" in endpoint or "127.0.0.1" in endpoint:
            return True
        return bool(self.config.api_key)


    def list_models(self) -> list[dict[str, Any]]:
        """Return the list of models available on the server."""
        self._detect_api_type()
        _, models_url = self._get_paths()
        try:
            data = self._request("GET", models_url)
        except LLMError:
            return []

        if isinstance(data, dict):
            if "data" in data and isinstance(data["data"], list):
                return data["data"]
            if "models" in data and isinstance(data["models"], list):
                # Ollama native format
                result = []
                for m in data["models"]:
                    name = m.get("name", m.get("model", ""))
                    result.append({"id": name, "name": name})
                return result
        if isinstance(data, list):
            return data
        return []

    def summarize_events(
        self,
        events: Sequence[dict[str, Any]],
        *,
        system_prompt: str = _SYSTEM_PROMPT,
    ) -> str:
        if not self.is_enabled():
            logger.info("LLM client disabled")
            return ""

        self._detect_api_type()
        model = self._resolve_model()
        if not model:
            logger.warning("No LLM model available on %s", self.config.endpoint)
            return ""

        # Clean up verbose/bulky metadata fields to fit within the LLM's context window
        cleaned_events = []
        for e in events:
            if isinstance(e, dict):
                cleaned = {
                    k: v for k, v in e.items()
                    if k not in (
                        "kexAlgs", "keyAlgs", "encCS", "macCS", "compCS", "langCS",
                        "hasshAlgorithms", "kexAlgorithms", "payload", "packet",
                        "payload_printable"
                    )
                }
                cleaned_events.append(cleaned)
            else:
                cleaned_events.append(e)

        events_text = "\n".join(json.dumps(e, separators=(",", ":")) for e in cleaned_events)

        if self.api_type == "ollama":
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze these eBPF events:\n{events_text}"},
                ],
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "num_predict": 1024,
                }
            }
        else:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze these eBPF events:\n{events_text}"},
                ],
                "temperature": 0.3,
                "max_tokens": 4096,
                "chat_id": "honeypot-ai",
            }

        completions_url, _ = self._get_paths()
        try:
            data = self._request("POST", completions_url, body=payload)
        except LLMError as exc:
            logger.warning("LLM request failed: %s", exc)
            return ""

        try:
            if self.api_type == "ollama":
                return data["message"]["content"].strip()
            else:
                return data["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, TypeError) as exc:
            logger.warning("Unexpected LLM response shape: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _detect_api_type(self) -> None:
        """Auto-detect the API interface type supported by the endpoint."""
        endpoint = self.config.endpoint.rstrip("/")
        if "/v1" in endpoint:
            self.api_type = "openai"
            return

        # 1. Try Ollama tags (must return application/json)
        try:
            req = urllib.request.Request(f"{endpoint}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    content_type = resp.headers.get("Content-Type", "")
                    if "application/json" in content_type.lower():
                        self.api_type = "ollama"
                        return
        except Exception:
            pass

        # 2. Try Open WebUI models (may return 401/403, but confirms endpoint exists)
        try:
            req = urllib.request.Request(f"{endpoint}/api/models", method="GET")
            if self.config.api_key:
                req.add_header("Authorization", f"Bearer {self.config.api_key}")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    content_type = resp.headers.get("Content-Type", "")
                    if "application/json" in content_type.lower():
                        self.api_type = "open_webui"
                        return
                elif resp.status == 401:
                    self.api_type = "open_webui"
                    return
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.api_type = "open_webui"
                return
        except Exception:
            pass

        self.api_type = "openai"

    def _get_paths(self) -> tuple[str, str]:
        """Return the completions and models URLs based on the detected API type."""
        endpoint = self.config.endpoint.rstrip("/")
        if "/v1" in endpoint:
            return f"{endpoint}/chat/completions", f"{endpoint}/models"
        if self.api_type == "ollama":
            return f"{endpoint}/api/chat", f"{endpoint}/api/tags"
        # Open WebUI format
        return f"{endpoint}/api/chat/completions", f"{endpoint}/api/models"

    def _resolve_model(self) -> str:
        """Return the configured model or auto-detect the first one."""
        if self.config.model:
            return self.config.model
        try:
            models = self.list_models()
            if models:
                model_id = models[0].get("id", models[0].get("name", ""))
                logger.info("Auto-detected LLM model: %s", model_id)
                return model_id
        except LLMError:
            pass
        return ""

    def _request(
        self,
        method: str,
        url: str,
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Issue an HTTP request with bearer auth."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        data_bytes: bytes | None = None
        if body is not None:
            data_bytes = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                raw = resp.read()
                try:
                    return json.loads(raw) if raw else {}
                except json.JSONDecodeError as exc:
                    raise LLMError(f"Failed to parse JSON response from {url}: {exc}. Response was: {raw[:200]!r}") from exc
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="ignore")
            except Exception:
                body = exc.reason
            raise LLMError(f"HTTP {exc.code} from {url}: {body}") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise LLMError(f"Connection to {url} failed: {exc}") from exc


class LLMError(Exception):
    """Raised when the LLM server is unreachable or returns an error."""
