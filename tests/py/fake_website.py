"""The website's owner API for signer tests: login, grants, revoke, customize.

Wraps ``fakes.opener`` (plans, reports, RPC) with what the desktop app adds.
The login and customize rules mirror the Anubis Automation website's; the real API
is exercised by the website's own tests.
"""

from __future__ import annotations

import io
import json
import secrets
import time
from dataclasses import dataclass, field
from email.message import Message
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse

from eth_abi import decode, encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address

import fakes
import signer_constants as c
from signer_constants import amount


def _gone(url: str, http_status: int, error: str, /, **extra: Any) -> HTTPError:
    """An HTTP error with a JSON body (``extra``: errorEn, code, params, status, ...)."""
    return HTTPError(url, http_status, "error", Message(), io.BytesIO(json.dumps({"error": error, **extra}).encode()))


class _Response(io.BytesIO):
    """urlopen-like response with headers."""

    def __init__(self, body: bytes, cookies: list[str] | None = None) -> None:
        super().__init__(body)
        self.headers = Message()
        for cookie in cookies or []:
            self.headers["Set-Cookie"] = cookie

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def row(owner: str, grant_id: str, *, status: str = "active", kind: str = "policy", key: str | None = None,
        bot: dict | None = None, until: int | None = None, calls: int | None = 256) -> dict[str, Any]:
    """One ``GET /api/grants`` row."""
    until = until if until is not None else int(time.time()) + 7 * 86400
    return {
        "grantId": grant_id, "kind": kind, "source": "site", "key": key or fakes.SESSION_KEY,
        "keyOrigin": "hosted", "bot": bot, "botId": "", "target": owner, "validAfter": None,
        "validUntil": None, "validAfterUnix": until - 8 * 86400, "validUntilUnix": until,
        "remainingCalls": calls, "status": status, "revocable": status in {"active", "not_yet_valid", "expired", "exhausted"},
        "references": [], "installBlock": 1, "installTx": "", "revokeTx": "", "rules": [],
    }


@dataclass
class Website:
    """Owner API state.

    Attributes:
        site: fakes.FakeSite; plans and reports.
        chain: fakes.FakeChain; the chain.
        grants: dict; owner (lowercase) -> rows.
        requests: list; (method, path) of every website request.
        session_cookies: list; session cookies issued.
        tamper: Callable | None; rewrites a customize answer.
    """

    site: fakes.FakeSite
    chain: fakes.FakeChain
    grants: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    requests: list[tuple[str, str]] = field(default_factory=list)
    session_cookies: list[str] = field(default_factory=list)
    challenges: dict[str, str] = field(default_factory=dict)
    sessions: dict[str, str] = field(default_factory=dict)
    login_domain: str = "anubis.sivilization.com"
    customized: list[dict[str, Any]] = field(default_factory=list)
    tamper: Any = None
    tamper_call: Any = None
    tamper_challenge: Any = None
    customize_status: int | None = None
    confirmations: list[tuple[str, str]] = field(default_factory=list)
    confirm_status: int = 200
    logged_out: int = 0
    bases: dict[str, tuple[str, list[dict[str, Any]]]] = field(default_factory=dict)
    scan_pages: int = 0

    def opener(self):  # noqa: ANN201 - test transport.
        """The combined urlopen replacement."""
        plain = fakes.opener(self.chain, self.site)

        def open_(request, timeout):  # noqa: ANN001, ANN202
            path = urlparse(request.full_url).path
            if not path.startswith("/api/") or path.startswith("/api/signer/plans/") and not path.endswith("/customize"):
                if path.startswith("/api/signer/plans/"):
                    self.requests.append((request.get_method(), path))
                return plain(request, timeout)
            self.requests.append((request.get_method(), path))
            return self.handle(request, path)

        return open_

    def _session(self, request) -> str:  # noqa: ANN001
        """The owner of the request's session cookie; 401 otherwise."""
        cookie = request.get_header("Cookie") or ""
        pairs = dict(item.split("=", 1) for item in cookie.split("; ") if "=" in item)
        owner = self.sessions.get(pairs.get("sessionid", ""))
        if owner is None:
            raise _gone(request.full_url, 401, "請先連接錢包並簽名登入。")
        return owner

    def _csrf(self, request) -> None:  # noqa: ANN001
        """Writes need the CSRF cookie echoed in a header, with an Origin."""
        cookie = request.get_header("Cookie") or ""
        pairs = dict(item.split("=", 1) for item in cookie.split("; ") if "=" in item)
        if not pairs.get("csrftoken") or request.get_header("X-csrftoken") != pairs["csrftoken"] or not request.get_header("Origin"):
            raise _gone(request.full_url, 403, "CSRF verification failed.")

    def handle(self, request, path: str):  # noqa: ANN001, ANN201, C901
        """Answer one website request."""
        url = request.full_url
        method = request.get_method()
        body = json.loads(request.data) if request.data else {}
        if path == "/api/csrf":
            return _Response(
                json.dumps({"csrfToken": "csrf-1", "origin": f"https://{self.login_domain}"}).encode(),
                ["csrftoken=csrf-1; Path=/; Secure; SameSite=Lax"],
            )
        if path.endswith("/customize"):
            return self.customize(url, path.split("/")[4], body)
        if path == "/api/auth/challenge":
            self._csrf(request)
            wallet = body["wallet"]
            domain = self.login_domain
            message = (
                f"{domain} wants you to sign in with your Ethereum account:\n{wallet}\n\n"
                f"登入 Anubis Automation。此簽名不會發送交易。\n\nURI: https://{domain}\nVersion: 1\n"
                f"Chain ID: 6714\nNonce: {secrets.token_hex(16)}\nIssued At: now\nExpiration Time: later"
            )
            if self.tamper_challenge:
                message = self.tamper_challenge(message)
            self.challenges[wallet] = message
            return _Response(json.dumps({"message": message}).encode())
        if path == "/api/auth/verify":
            self._csrf(request)
            wallet = body["wallet"]
            if self.challenges.get(wallet) != body["message"]:
                raise _gone(url, 400, "簽名請求已失效，請重新連接。")
            signer = Account.recover_message(encode_defunct(text=body["message"]), signature=body["signature"])
            if signer.lower() != wallet:
                raise _gone(url, 400, "簽名與錢包地址不符。")
            del self.challenges[wallet]
            session = secrets.token_hex(16)
            self.sessions[session] = wallet
            self.session_cookies.append(session)
            # Django rotates the CSRF token on login.
            return _Response(
                json.dumps({"wallet": wallet}).encode(),
                [f"sessionid={session}; HttpOnly; Path=/", "csrftoken=csrf-2; Path=/"],
            )
        if path == "/api/auth/logout":
            self._csrf(request)
            self.logged_out += 1
            return _Response(b'{"ok": true}', ['sessionid=""; Max-Age=0; Path=/'])
        owner = self._session(request)
        if path == "/api/grants" and method == "GET":
            return self.listing(owner)
        parts = path.strip("/").split("/")
        if parts[:2] == ["api", "grants"] and len(parts) == 4:
            self._csrf(request)
            grant_id = parts[2]
            found = next((item for item in self.grants.get(owner, []) if item["grantId"] == grant_id), None)
            if found is None:
                raise _gone(url, 404, "找不到此 Grant。")
            if parts[3] == "revoke-call":
                return self.revoke_call(url, owner, grant_id, found)
            if parts[3] == "revoke-confirm":
                self.confirmations.append((grant_id, body["txHash"]))
                if self.confirm_status != 200:
                    raise _gone(url, self.confirm_status, "refused")
                found["status"] = "revoked"
                found["revocable"] = False
                return _Response(json.dumps({"ok": True, "status": "revoked", "txHash": body["txHash"], "stoppedBots": [7]}).encode())
        raise AssertionError(f"unexpected website request {method} {url}")

    def listing(self, owner: str):  # noqa: ANN201
        """``GET /api/grants``."""
        percent = 100 if self.scan_pages <= 0 else 50
        self.scan_pages -= 1
        return _Response(
            json.dumps(
                {
                    "owner": owner, "chainId": 6714, "chainTime": "2026-11-09T00:00:00Z", "headBlock": 100,
                    "delegation": {"delegated": True, "target": c.IMPLEMENTATION, "expected": True},
                    "scan": {"complete": percent == 100, "percent": percent, "startBlock": 1, "scannedFrom": 1, "scannedTo": 100, "headBlock": 100},
                    "hostedSessionKey": fakes.SESSION_KEY, "truncated": False, "grants": self.grants.get(owner, []),
                }
            ).encode()
        )

    def revoke_call(self, url: str, owner: str, grant_id: str, found: dict[str, Any]):  # noqa: ANN201
        """``POST /api/grants/<id>/revoke-call``."""
        table = self.chain.policy if found["kind"] == "policy" else self.chain.session
        if grant_id not in table.get(owner, {}):
            raise _gone(url, 409, "已撤銷", status="revoked")
        code = self.chain.code.get(owner, b"")
        if code and code not in fakes.HELIX_CODES:
            raise _gone(url, 409, "委派給其他合約", status="inactive", reason="otherDelegation")
        call = {
            "to": owner, "data": c.REVOKE_SELECTORS[found["kind"]] + grant_id[2:], "value": "0x0", "chainId": 6714,
            "grantId": grant_id, "kind": found["kind"], "status": found["status"], "gasFeePercent": "0",
        }
        if self.tamper_call:
            call = self.tamper_call(call)
        return _Response(json.dumps(call).encode())

    def customize(self, url: str, token: str, body: dict[str, Any]):  # noqa: ANN201
        """``POST /api/signer/plans/<token>/customize``: same bounds as the website."""
        if self.customize_status:
            raise _gone(url, self.customize_status, "stopped")
        plan = self.site.plans.get(token)
        if plan is None:
            raise _gone(url, 404, "unknown")
        options = body.get("grant") or {}
        self.customized.append(options)
        data = self.bases.setdefault(token, (plan["data"], plan["rules"]))
        answer = self.apply(url, plan, data[0], data[1], options)
        self.site.plans[token] = dict(answer)
        if self.tamper:
            answer = self.tamper(answer)
        return _Response(json.dumps(answer).encode())

    def apply(self, url: str, plan: dict, data: str, previews: list, options: dict) -> dict[str, Any]:
        """Re-encode the planner's calldata with the requested values."""
        grant_id, grant, raw = decode(list(c.INSTALL_TYPES), bytes.fromhex(data[10:]))
        rules = [list(item) for item in raw]
        key, bot, after, default_until, default_calls = grant
        now = int(time.time())
        until = int(options.get("validUntil") or default_until)
        minimum, maximum = now + 3600, now + 90 * 86400
        if not minimum <= until <= maximum:
            raise _gone(
                url, 400, "到期時間超出範圍。", errorEn=f"The expiry must be between {minimum} and {maximum}.",
                code="bounds.expiry", params={"min": minimum, "next": minimum - 3600, "max": maximum, "days": 90},
            )
        calls = int(options.get("remainingCalls") or default_calls)
        most = max(default_calls, len(rules) * 4 * ((max(until, default_until) - now) // 86400 + 2))
        if not len(rules) <= calls <= min(4096, most):
            raise _gone(
                url, 400, "呼叫次數超出範圍。", errorEn=f"The call count must be between {len(rules)} and {min(4096, most)}.",
                code="bounds.calls",
                params={"min": len(rules), "max": min(4096, most), "perRuleDay": 4, "days": (max(until, default_until) - now) // 86400 + 2, "cap": 4096},
            )
        decimals = [18] * len(rules)
        for change in options.get("rules") or []:
            index = change["index"]
            need_call, need_day = int(raw[index][4]), int(raw[index][6])
            per_call = int(float(change.get("maxPerCall", need_call / 10**18)) * 10**18)
            per_day = int(float(change.get("maxPerDay", max(need_day, per_call) / 10**18)) * 10**18)
            if not need_call <= per_call <= need_call * 2:
                raise _gone(
                    url, 400, "每次上限超出範圍。", errorEn=f"Rule {index + 1}: the per-call cap is out of range.",
                    code="bounds.perCall",
                    params={"rule": index + 1, "unit": "DAI", "min": amount(need_call, 18), "max": amount(need_call * 2, 18), "factor": 2},
                )
            if not max(need_day, per_call) <= per_day <= need_day * 4:
                raise _gone(
                    url, 400, "每日上限超出範圍。", errorEn=f"Rule {index + 1}: the per-day cap is out of range.",
                    code="bounds.perDay",
                    params={"rule": index + 1, "unit": "DAI", "min": amount(max(need_day, per_call), 18), "max": amount(need_day * 4, 18), "factor": 4},
                )
            rules[index][4], rules[index][6] = per_call, per_day
        encoded = c.INSTALL_SELECTOR + encode(
            list(c.INSTALL_TYPES), [grant_id, (key, bot, after, until, calls), [tuple(item) for item in rules]]
        ).hex()
        return {
            **plan,
            "data": encoded,
            "validUntil": until,
            "remainingCalls": calls,
            "rules": [
                {**shown, "maxPerCall": amount(int(item[4]), places), "maxPerDay": amount(int(item[6]), places)}
                for shown, item, places in zip(previews, rules, decimals, strict=True)
            ],
            "customization": {"customized": ["edited"]},
            "bounds": {
                "validUntil": {"min": minimum, "max": maximum, "default": default_until},
                "remainingCalls": {"min": len(rules), "max": min(4096, most), "default": default_calls},
                "rules": [
                    {
                        "index": index, "method": shown["method"], "unit": "DAI",
                        "maxPerCall": {"min": amount(int(item[4]), 18), "max": amount(int(item[4]) * 2, 18)},
                        "maxPerDay": {"min": amount(int(item[6]), 18), "max": amount(int(item[6]) * 4, 18)},
                    }
                    for index, (shown, item) in enumerate(zip(previews, raw, strict=True))
                ],
            },
        }


__all__ = ["Website", "row", "to_checksum_address"]
