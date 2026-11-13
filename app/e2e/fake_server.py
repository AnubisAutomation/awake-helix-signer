"""Serve the signer tests' fake website and chain over HTTP on 127.0.0.1.

The signer test fakes model the website (plans, customize, login, grants,
revoke-call/confirm, report) and an Anubis JSON-RPC node that executes
EIP-7702 transactions (``tests/py/fakes.py``, ``tests/py/fake_website.py``,
``tests/py/signer_constants.py``; the CLI tests serve the same fakes with
``tests/py/server.py``). This
wraps their in-process openers in a real HTTP server with the app's control
endpoints so the Rust app (its command layer and the built desktop app) can be
tested end to end against them:

    python -I app/e2e/fake_server.py <config.json>   (needs eth-account)

It writes ``config.json`` once it listens: ``api`` (website base), ``rpc``
(``<api>/rpc``), ``constants`` (a ``--dev-constants`` file pinning the fake
implementation's code hash and the test attestation key), ``privateKey`` and
``owner`` (a funded test owner, already delegated to Helix, with two active
grants on chain), and ``signToken`` (a fresh grant plan). Test-only keys; never
use them anywhere else.

Control endpoints (tests only): ``POST /__plan`` makes another grant plan and
answers ``{"token"}``; ``GET /__state`` answers the transactions, reports,
customize requests and revoke confirmations seen so far.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request

RS = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RS / "tests/py")]

import fake_website  # noqa: E402
import fakes  # noqa: E402
from eth_account import Account  # noqa: E402
from eth_utils import keccak  # noqa: E402

OWNER_KEY = keccak(text="awake-helix app end-to-end test owner")
OWNER = Account.from_key(OWNER_KEY).address
LOCK = threading.Lock()


class World:
    """The fake chain, website and their seeded state."""

    def __init__(self, base: str) -> None:
        self.base = base
        self.chain = fakes.FakeChain()
        self.site = fakes.FakeSite()
        host = base.split("://", 1)[1]
        self.web = fake_website.Website(self.site, self.chain, login_domain=host)
        owner = OWNER.lower()
        self.chain.balances[owner] = 10**21
        self.chain.delegate(owner)
        self.chain.nonces[owner] = 1
        rows = []
        for index, status in enumerate(("active", "active", "expired", "revoked")):
            grant_id = "0x" + keccak(text=f"e2e grant {index}").hex()
            if status != "revoked":
                self.chain.policy.setdefault(owner, {})[grant_id] = fakes.SESSION_KEY.lower()
            bot = {"id": 12 + index, "script": ["dai-power", "lgns-power", "activate", "dai-power"][index], "status": "active"}
            rows.append(fake_website.row(owner, grant_id, status=status, bot=bot, calls=[254, 512, 3, None][index]))
        self.web.grants[owner] = rows
        self.counter = 0

    def new_plan(self) -> str:
        """A fresh grant plan for the owner, reporting to this server."""
        self.counter += 1
        token = f"tok_e2e_{self.counter:04d}_" + "A" * 24
        plan = fakes.grant_plan(OWNER)
        plan["reportUrl"] = f"{self.base}/api/signer/plans/{token}/report"
        self.site.plans[token] = plan
        return token

    def state(self) -> dict[str, object]:
        return {
            "sent": [{"type": item["type"], "sender": item["sender"], "authorities": item["authorities"]} for item in self.chain.sent],
            "reports": self.site.reports,
            "customized": self.web.customized,
            "confirmations": self.web.confirmations,
            "loggedOut": self.web.logged_out,
            "policy": {owner: sorted(grants) for owner, grants in self.chain.policy.items()},
        }


def handler_for(world: World, opener):  # noqa: ANN001, ANN201 - test transport.
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_: object) -> None:  # quiet
            return

        def _answer(self, status: int, body: bytes, headers: list[tuple[str, str]] = ()) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            data = self.rfile.read(length) if length else None
            if self.path == "/__state":
                with LOCK:
                    self._answer(200, json.dumps(world.state()).encode())
                return
            if self.path == "/__plan":
                with LOCK:
                    self._answer(200, json.dumps({"token": world.new_plan()}).encode())
                return
            headers = {name: value for name, value in self.headers.items() if name.lower() not in {"host", "content-length", "connection"}}
            request = Request(world.base + self.path, data=data, method=self.command, headers=headers)
            try:
                with LOCK:
                    response = opener(request, 30)
                    body = response.read()
                    found = getattr(response, "headers", None)
                cookies = [("Set-Cookie", value) for value in (found.get_all("Set-Cookie") or [])] if found is not None and hasattr(found, "get_all") else []
                self._answer(200, body, cookies)
            except HTTPError as error:
                body = error.read() or b"{}"
                cookies = [("Set-Cookie", value) for value in (error.headers.get_all("Set-Cookie") or [])] if error.headers else []
                self._answer(error.code, body, cookies)
            except AssertionError as error:
                self._answer(500, json.dumps({"error": f"fake server: {error}"}).encode())

        do_GET = _handle
        do_POST = _handle

    return Handler


def main(argv: list[str]) -> int:
    out = Path(argv[1]) if len(argv) > 1 else None
    server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    world = World(base)
    server.RequestHandlerClass = handler_for(world, world.web.opener())
    constants = fakes.dev_constants()
    folder = out.parent if out else Path(".")
    folder.mkdir(parents=True, exist_ok=True)
    constants_file = folder / "dev-constants.json"
    constants_file.write_text(json.dumps(constants, indent=2) + "\n", encoding="utf-8")
    config = {
        "api": base,
        "rpc": f"{base}/rpc",
        "constants": str(constants_file),
        "privateKey": "0x" + OWNER_KEY.hex(),
        "owner": OWNER,
        "signToken": world.new_plan(),
        "grants": [row["grantId"] for row in world.web.grants[OWNER.lower()]],
    }
    text = json.dumps(config, indent=2)
    if out:
        out.write_text(text + "\n", encoding="utf-8")
    print(text, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
