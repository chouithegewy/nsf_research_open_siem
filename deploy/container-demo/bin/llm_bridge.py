#!/usr/bin/env python3
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class LLMBridgeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._proxy()

    def do_POST(self) -> None:
        self._proxy()

    def do_OPTIONS(self) -> None:
        self._proxy()

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"llm-bridge: {self.address_string()} - {fmt % args}", flush=True)

    def _proxy(self) -> None:
        if self.path == "/healthz":
            self._send_bytes(200, b"ok\n", {"Content-Type": "text/plain"})
            return

        upstream = os.getenv("UPSTREAM_LLM_ENDPOINT", "").rstrip("/")
        if not upstream:
            self._send_bytes(
                503,
                b"UPSTREAM_LLM_ENDPOINT is not configured\n",
                {"Content-Type": "text/plain"},
            )
            return

        target = urllib.parse.urljoin(f"{upstream}/", self.path.lstrip("/"))
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "host"
        }
        upstream_token = _upstream_bearer_token()
        if upstream_token:
            headers["Authorization"] = f"Bearer {upstream_token}"

        request = urllib.request.Request(
            target,
            data=body if body else None,
            headers=headers,
            method=self.command,
        )
        timeout = float(os.getenv("LLM_BRIDGE_TIMEOUT", "120"))
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response_headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower() not in HOP_BY_HOP_HEADERS
                }
                payload = response.read()
                self._send_bytes(response.status, payload, response_headers)
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            headers = {
                key: value
                for key, value in exc.headers.items()
                if key.lower() not in HOP_BY_HOP_HEADERS
            }
            self._send_bytes(exc.code, payload, headers)
        except Exception as exc:
            message = f"LLM upstream request failed: {exc}\n".encode("utf-8")
            self._send_bytes(502, message, {"Content-Type": "text/plain"})

    def _send_bytes(self, status: int, payload: bytes, headers: dict[str, str]) -> None:
        self.send_response(status)
        sent_length = False
        for key, value in headers.items():
            if key.lower() == "content-length":
                sent_length = True
            self.send_header(key, value)
        if not sent_length:
            self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> int:
    port = int(os.getenv("LLM_BRIDGE_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), LLMBridgeHandler)
    print(f"llm-bridge listening on :{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("llm-bridge stopping", file=sys.stderr, flush=True)
    return 0


def _upstream_bearer_token() -> str:
    token_file = os.getenv("UPSTREAM_LLM_BEARER_TOKEN_FILE", "")
    for key in ("DEMO_UPSTREAM_LLM_BEARER_TOKEN", "LLM_API_KEY", "UPSTREAM_LLM_BEARER_TOKEN"):
        value = _env_file_value(token_file, key) if token_file else ""
        if value:
            return value
    return os.getenv("UPSTREAM_LLM_BEARER_TOKEN", "").strip()


def _env_file_value(path: str, key: str) -> str:
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                name, value = stripped.split("=", 1)
                if name == key:
                    return value.strip().strip("\"'")
    except OSError:
        return ""
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
