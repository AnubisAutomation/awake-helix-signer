"""Serve the in-memory fakes (``fakes.py``, ``fake_website.py``) over HTTP.

One loopback port answers everything the signer talks to:

* ``POST /rpc``: the fake Anubis chain (JSON-RPC);
* ``/api/signer/plans/...``: plans, reports and customize;
* ``/api/csrf``, ``/api/auth/...``, ``/api/grants...``: the owner API;
* ``POST /api/signer/install-checks/<token>/ping``: the install check.

Requests are turned into urllib-like request objects and handed to the
fakes' ``opener``, so the same fake code backs the HTTP tests of the signer
binary (``test_cli.py``) and, through ``app/e2e/fake_server.py``, the app's.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError

import fake_website
import fakes


class FakeRequest:
    """The parts of ``urllib.request.Request`` the fakes read."""

    def __init__(self, url: str, method: str, headers: dict[str, str], data: bytes | None) -> None:
        self.full_url = url
        self._method = method
        self._headers = {key.lower(): value for key, value in headers.items()}
        self.data = data

    def get_method(self) -> str:
        return self._method

    def get_header(self, name: str, default: str | None = None) -> str | None:
        return self._headers.get(name.lower(), default)


class Fake:
    """Fake chain + website on one loopback port.

    Attributes:
        chain: fakes.FakeChain; the chain.
        site: fakes.FakeSite; plans and reports.
        backend: fake_website.Website; the owner API.
        url: str; ``http://127.0.0.1:<port>``.
        pings: list; (token, body) of every install-check ping.
        ping_status: int; HTTP status the ping answers.
        ping_answer: dict; JSON the ping answers with 200.
        log: list; (method, path, headers, body) of every request.
    """

    def __init__(self) -> None:
        self.chain = fakes.FakeChain()
        self.site = fakes.FakeSite()
        self.backend = fake_website.Website(self.site, self.chain)
        self.pings: list[tuple[str, dict[str, Any]]] = []
        self.ping_status = 200
        self.ping_answer: dict[str, Any] = {"ok": True, "status": "confirmed"}
        self.log: list[tuple[str, str, dict[str, str], bytes]] = []
        self.lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_: Any) -> None:  # quiet: URLs contain plan tokens
                return

            def _send(self, status: int, body: bytes, cookies: list[str]) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for cookie in cookies:
                    self.send_header("Set-Cookie", cookie)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                data = self.rfile.read(length) if length else None
                headers = {key: value for key, value in self.headers.items()}
                with fake.lock:
                    fake.log.append((self.command, self.path, headers, data or b""))
                parts = self.path.split("?")[0].strip("/").split("/")
                if parts[:3] == ["api", "signer", "install-checks"] and parts[4:] == ["ping"] and self.command == "POST":
                    with fake.lock:
                        fake.pings.append((parts[3], json.loads(data or b"{}")))
                    if fake.ping_status != 200:
                        return self._send(fake.ping_status, json.dumps({"error": "refused"}).encode(), [])
                    return self._send(200, json.dumps(fake.ping_answer).encode(), [])
                request = FakeRequest(fake.url + self.path, self.command, headers, data)
                try:
                    with fake.lock:
                        response = fake.backend.opener()(request, 30)
                        body = response.read()
                        message = getattr(response, "headers", None)
                    cookies = message.get_all("Set-Cookie") if hasattr(message, "get_all") else []
                    self._send(200, body, cookies or [])
                except HTTPError as error:
                    body = error.read() or b"{}"
                    message = error.headers
                    cookies = message.get_all("Set-Cookie") if hasattr(message, "get_all") else []
                    self._send(error.code, body, cookies or [])
                except AssertionError as error:
                    self._send(404, json.dumps({"error": str(error)}).encode(), [])

            do_GET = _handle  # noqa: N815 - http.server API.
            do_POST = _handle  # noqa: N815 - http.server API.

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.rpc = f"{self.url}/rpc"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        """Stop the server."""
        self.server.shutdown()
        self.server.server_close()
