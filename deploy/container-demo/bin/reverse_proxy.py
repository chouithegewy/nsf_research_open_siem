#!/usr/bin/env python3
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import select
import socket
import socketserver
import threading
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


class HTTPReverseProxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._proxy()

    def do_HEAD(self) -> None:
        self._proxy()

    def do_POST(self) -> None:
        self._proxy()

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"reverse-proxy/http: {self.address_string()} - {fmt % args}", flush=True)

    def _proxy(self) -> None:
        if self.path == "/healthz":
            self._send_bytes(200, b"ok\n", {"Content-Type": "text/plain"})
            return

        upstream = os.getenv("HTTP_UPSTREAM", "http://dashboard:80").rstrip("/")
        target = urllib.parse.urljoin(f"{upstream}/", self.path.lstrip("/"))
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "host"
        }
        request = urllib.request.Request(
            target,
            data=body if body else None,
            headers=headers,
            method=self.command,
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                response_headers = {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower() not in HOP_BY_HOP_HEADERS
                }
                payload = b"" if self.command == "HEAD" else response.read()
                self._send_bytes(response.status, payload, response_headers)
        except urllib.error.HTTPError as exc:
            payload = b"" if self.command == "HEAD" else exc.read()
            headers = {
                key: value
                for key, value in exc.headers.items()
                if key.lower() not in HOP_BY_HOP_HEADERS
            }
            self._send_bytes(exc.code, payload, headers)
        except Exception as exc:
            self._send_bytes(502, f"HTTP upstream failed: {exc}\n".encode(), {"Content-Type": "text/plain"})

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
        if self.command != "HEAD":
            self.wfile.write(payload)


class ThreadedTCPProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class TCPProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        upstream_host = os.getenv("TCP_UPSTREAM_HOST", "cowrie")
        upstream_port = int(os.getenv("TCP_UPSTREAM_PORT", "2222"))
        print(
            f"reverse-proxy/tcp: {self.client_address[0]}:{self.client_address[1]} -> {upstream_host}:{upstream_port}",
            flush=True,
        )
        try:
            with socket.create_connection((upstream_host, upstream_port), timeout=10) as upstream:
                self._forward(self.request, upstream)
        except Exception as exc:
            print(f"reverse-proxy/tcp upstream failed: {exc}", flush=True)

    def _forward(self, client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        for sock in sockets:
            sock.setblocking(False)
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 30)
            if errored or not readable:
                return
            for source in readable:
                try:
                    data = source.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                target = upstream if source is client else client
                try:
                    target.sendall(data)
                except OSError:
                    return


def main() -> int:
    http_port = int(os.getenv("HTTP_LISTEN_PORT", "80"))
    tcp_port = int(os.getenv("TCP_LISTEN_PORT", "2222"))

    http_server = ThreadingHTTPServer(("0.0.0.0", http_port), HTTPReverseProxy)
    tcp_server = ThreadedTCPProxy(("0.0.0.0", tcp_port), TCPProxyHandler)

    threads = [
        threading.Thread(target=http_server.serve_forever, daemon=True),
        threading.Thread(target=tcp_server.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    print(f"reverse-proxy listening on HTTP :{http_port} and TCP :{tcp_port}", flush=True)
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        http_server.shutdown()
        tcp_server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
