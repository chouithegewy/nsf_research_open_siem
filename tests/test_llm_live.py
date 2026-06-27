from __future__ import annotations

import json
import os
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from honeypot_ai.llm import LLMClient, LLMConfig, LLMError


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENDPOINT = "http://10.20.10.117:8080"
DEFAULT_MODEL = "qwen/qwen3.5-9b"
DOTENV_PATHS = (ROOT / ".env", ROOT / "deploy/container-demo/.env")
CREDENTIALS_PATH = ROOT / "credentials.txt"


def _read_dotenv(paths: tuple[Path, ...] = DOTENV_PATHS) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            name, value = stripped.split("=", 1)
            values[name.strip()] = value.strip().strip("\"'")
    return values


_DOTENV = _read_dotenv()


def _read_credentials(path: Path = CREDENTIALS_PATH) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        separator = "=" if "=" in stripped else ":" if ":" in stripped else ""
        if not separator:
            continue
        name, value = stripped.split(separator, 1)
        values[name.strip().lower()] = value.strip().strip("\"'")
    return values


_CREDENTIALS = _read_credentials()


def _setting(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name) or _DOTENV.get(name)
        if value:
            return value
    return default


def _int_setting(*names: str, default: int) -> int:
    raw = _setting(*names, default=str(default))
    try:
        return int(raw)
    except ValueError:
        return default


def _live_test_enabled() -> bool:
    return os.getenv("RUN_LIVE_LLM_TEST", "").lower() in {"1", "true", "yes"}


def _credential(*names: str) -> str:
    for name in names:
        value = _setting(name)
        if value:
            return value
        value = _CREDENTIALS.get(name.lower())
        if value:
            return value
    return ""


def _open_webui_signin_token(endpoint: str, username: str, password: str, timeout: int) -> str:
    url = f"{endpoint.rstrip('/')}/api/v1/auths/signin"
    payload = json.dumps({"email": username, "password": password}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        raise LLMError(f"Open WebUI signin failed with HTTP {exc.code}: {body}") from exc
    except (OSError, TimeoutError, json.JSONDecodeError) as exc:
        raise LLMError(f"Open WebUI signin failed: {exc}") from exc

    token = _extract_token(data)
    if not token:
        raise LLMError(f"Open WebUI signin did not return a token. Response keys: {sorted(data)}")
    return token


def _extract_token(data: object) -> str:
    if not isinstance(data, dict):
        return ""
    for key in ("token", "access_token", "api_key"):
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    for key in ("data", "user"):
        token = _extract_token(data.get(key))
        if token:
            return token
    return ""


def _post_chat_completion(
    *,
    endpoint: str,
    token: str,
    model: str,
    prompt: str,
    timeout: int,
    max_tokens: int,
) -> tuple[str, str, int, str]:
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Return only the final answer text for this connectivity test.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        "max_tokens": max_tokens,
        "chat_id": "honeypot-ai-live-llm-test",
    }
    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}/api/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        raise LLMError(f"chat completion failed with HTTP {exc.code}: {body}") from exc
    except (OSError, TimeoutError, json.JSONDecodeError) as exc:
        raise LLMError(f"chat completion failed: {exc}") from exc

    try:
        choice = data["choices"][0]
        message = choice["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"unexpected chat completion response shape: {data}") from exc

    content = str(message.get("content") or "").strip()
    reasoning_content = str(message.get("reasoning_content") or "")
    finish_reason = str(choice.get("finish_reason") or "")
    return content, finish_reason, len(reasoning_content), json.dumps(data)[:1000]


@unittest.skipUnless(
    _live_test_enabled(),
    "set RUN_LIVE_LLM_TEST=1 to prompt the live NetBird LLM",
)
class LiveLLMNetBirdTests(unittest.TestCase):
    def test_qwen_chat_completion_prompt_returns_text(self) -> None:
        endpoint = _setting(
            "LIVE_LLM_ENDPOINT",
            "DEMO_UPSTREAM_LLM_ENDPOINT",
            "LLM_ENDPOINT",
            default=DEFAULT_ENDPOINT,
        )
        model = _setting("LIVE_LLM_MODEL", "DEMO_LLM_MODEL", "LLM_MODEL", default=DEFAULT_MODEL)
        timeout = _int_setting("LIVE_LLM_TIMEOUT", "LLM_TIMEOUT", default=300)
        token_source = "none"
        token = _setting("LIVE_LLM_BEARER_TOKEN", "LLM_BEARER_TOKEN")
        if token:
            token_source = "bearer-token-env"
        else:
            username = _credential("OPEN_WEBUI_USER", "OPEN_WEBUI_USERNAME", "open_webui_user")
            password = _credential("OPEN_WEBUI_PASS", "OPEN_WEBUI_PASSWORD", "open_webui_pass")
            if username and password:
                token = _open_webui_signin_token(endpoint, username, password, timeout)
                token_source = "open-webui-signin"
            else:
                token = _setting("DEMO_UPSTREAM_LLM_BEARER_TOKEN", "LLM_API_KEY")
                if token:
                    token_source = "api-key-env"

        client = LLMClient(
            LLMConfig(
                endpoint=endpoint,
                bearer_token=token,
                model=model,
                enabled=True,
                timeout=timeout,
                max_tokens=_int_setting("LIVE_LLM_MAX_TOKENS", "LLM_MAX_TOKENS", default=2048),
                chat_id="honeypot-ai-live-llm-test",
            )
        )

        self.assertTrue(client.is_enabled(), f"refusing unsafe LLM endpoint: {endpoint}")

        prompt = _setting(
            "LIVE_LLM_PROMPT",
            default=(
                "Say exactly: LLM test OK: dashboard can reach "
                f"{model} over NetBird."
            ),
        )

        try:
            response, finish_reason, reasoning_len, raw_preview = _post_chat_completion(
                endpoint=endpoint,
                token=token,
                model=model,
                prompt=prompt,
                timeout=timeout,
                max_tokens=_int_setting(
                    "LIVE_LLM_MAX_TOKENS",
                    "LLM_MAX_TOKENS",
                    default=2048,
                ),
            )
        except LLMError as exc:
            self.fail(
                "Live LLM POST failed "
                f"(endpoint={endpoint}, model={model}, token_source={token_source}, "
                f"token_present={bool(token)}): {exc}"
            )

        if not response:
            self.fail(
                "Live LLM POST returned no visible assistant content "
                f"(finish_reason={finish_reason}, reasoning_chars={reasoning_len}). "
                f"Raw response preview: {raw_preview}"
            )

        print("\nLIVE_LLM_RESPONSE_BEGIN")
        print(f"endpoint={endpoint}")
        print(f"model={model}")
        print(f"auth={token_source}")
        print(f"finish_reason={finish_reason}")
        print(response)
        print("LIVE_LLM_RESPONSE_END")


if __name__ == "__main__":
    unittest.main(verbosity=2)
