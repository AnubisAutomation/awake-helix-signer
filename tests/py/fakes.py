"""In-memory Anubis chain and website for signer tests (no network).

Carried over from the former Python signer's tests; the constants come from
``signer_constants.py`` (mirroring the Rust core's constants.rs).
"""

from __future__ import annotations

import io
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse

import rlp
from eth_abi import decode, encode
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_account.typed_transactions import TypedTransaction
from eth_keys import keys as eth_keys
from eth_utils import keccak, to_checksum_address
from hexbytes import HexBytes

import signer_constants as c
from signer_constants import attestation_typed_data

IMPLEMENTATION_CODE = bytes.fromhex("6080604052") + b"helix-test-implementation"
API = "https://anubis.sivilization.com"
RPC = "https://rpc.anubispace.org"
TOKEN = "tok_" + "A" * 40


# Test-only keys, never used outside these tests: the platform's attestation
# key and one bot's session key.
ATTESTOR = Account.from_key(keccak(text="awake-helix signer tests: attestation key"))
SESSION_KEY = Account.from_key(keccak(text="awake-helix signer tests: session key")).address


def dev_constants() -> dict[str, str]:
    """The ``--dev-constants`` document of these fakes."""
    return {
        "implementation": c.IMPLEMENTATION,
        "implementationCodeHash": "0x" + keccak(IMPLEMENTATION_CODE).hex(),
        "attestationAddress": ATTESTOR.address,
    }


def attestation(owner: str, bot_bytes: bytes, session_key: str, *, signer: Any = ATTESTOR,
                chain_id: int = 6714) -> dict[str, Any]:
    """Attest a session key as the Awake Helix website does."""
    signable = encode_typed_data(
        full_message=attestation_typed_data(chain_id, to_checksum_address(owner), bot_bytes, to_checksum_address(session_key))
    )
    return {
        "version": c.ATTESTATION_VERSION,
        "chainId": chain_id,
        "owner": to_checksum_address(owner),
        "botId": str(uuid.UUID(bytes=bot_bytes)),
        "sessionKey": to_checksum_address(session_key),
        "signature": "0x" + bytes(signer.sign_message(signable).signature).hex(),
    }


def rule(kind: int, target: str, maximum: int, *, token_in: str = c.ZERO, counterparty: str = c.ZERO,
         secondary: int = 0, daily: int | None = None, price: int = 0, deadline: int = 0) -> tuple:
    """Encode one rule like the website's grant planner."""
    return (kind, target, token_in, counterparty, maximum, secondary, maximum if daily is None else daily, price, deadline, 0, 0)


def preview(raw: tuple) -> dict[str, Any]:
    """Website-style preview of a rule."""
    return {
        "kind": raw[0],
        "method": c.RULE_METHODS[raw[0]].split("(")[0],
        "target": to_checksum_address(raw[1]),
        "counterparty": to_checksum_address(raw[3]),
        "maxPerCall": "1",
        "maxPerDay": "1",
        "unit": "DAI",
        "maxSecondaryDai": "0",
        "minimumOutputPerInputWad": str(raw[7]),
        "maxDeadlineDelaySeconds": raw[8],
    }


def install_data(grant_id: bytes, grant: tuple, rules: list[tuple]) -> str:
    """installPolicyGrant calldata."""
    return c.INSTALL_SELECTOR + encode(list(c.INSTALL_TYPES), [grant_id, grant, rules]).hex()


def grant_plan(owner: str, *, now: int | None = None, rules: list[tuple] | None = None,
               session_key: str = SESSION_KEY, valid_seconds: int = 7 * 86400, calls: int = 256) -> dict[str, Any]:
    """A plan exactly as the website would serve it (DAI Power, 10 DAI)."""
    current = int(time.time()) if now is None else now
    rules = rules if rules is not None else [
        rule(0, c.DAI, 10 * 10**18, counterparty=c.LEDGER),
        rule(1, c.LEDGER, 10 * 10**18),
    ]
    grant_id = keccak(text=f"grant-{owner}-{current}-{uuid.uuid4()}")
    bot_bytes = uuid.uuid4().bytes
    grant = (session_key, bot_bytes, current - 60, current + valid_seconds, calls)
    return {
        "schema": c.PLAN_SCHEMA,
        "kind": "grant",
        "chainId": 6714,
        "owner": owner,
        "implementation": c.IMPLEMENTATION,
        "to": owner,
        "value": "0x0",
        "data": install_data(grant_id, grant, rules),
        "grantId": "0x" + grant_id.hex(),
        "sessionKey": session_key,
        # Always the platform's real key: a foreign session_key is a tampered plan.
        "sessionKeyAttestation": attestation(owner, bot_bytes, SESSION_KEY),
        "validUntil": current + valid_seconds,
        "rules": [preview(item) for item in rules],
        "bot": {"id": 7, "script": "dai-power"},
        "expiresAt": "2026-11-07T12:15:00+00:00",
        "reportUrl": f"{API}/api/signer/plans/{TOKEN}/report",
    }


def revoke_plan(owner: str, grant_id: str, kind: str = "policy") -> dict[str, Any]:
    """A revocation plan as the website serves it."""
    return {
        "schema": c.PLAN_SCHEMA,
        "kind": "revoke",
        "chainId": 6714,
        "owner": owner,
        "implementation": c.IMPLEMENTATION,
        "to": owner,
        "value": "0x0",
        "grantId": grant_id,
        "grantKind": kind,
        "data": c.REVOKE_SELECTORS[kind] + grant_id[2:],
        "reportUrl": f"{API}/api/signer/plans/{TOKEN}/report",
    }


def authority(entry: dict[str, Any]) -> str:
    """Recover an EIP-7702 authorization's signer."""
    message = b"\x05" + rlp.encode([entry["chainId"], bytes(entry["address"]), entry["nonce"]])
    signature = eth_keys.Signature(vrs=(entry["yParity"], entry["r"], entry["s"]))
    return signature.recover_public_key_from_msg_hash(keccak(message)).to_checksum_address()


class _Response(io.BytesIO):
    """urlopen-like response."""

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass
class FakeChain:
    """Enough of Anubis for the signer flow."""

    chain_id: int = 6714
    gas_price: int = 12 * 10**9
    base_fee: int = 0
    timestamp: int = field(default_factory=lambda: int(time.time()))
    code: dict[str, bytes] = field(default_factory=dict)
    nonces: dict[str, int] = field(default_factory=dict)
    balances: dict[str, int] = field(default_factory=dict)
    policy: dict[str, dict[str, str]] = field(default_factory=dict)
    session: dict[str, dict[str, str]] = field(default_factory=dict)
    receipts: dict[str, dict[str, Any]] = field(default_factory=dict)
    sent: list[dict[str, Any]] = field(default_factory=list)
    estimate_with_authorization: bool = True
    calls: list[str] = field(default_factory=list)
    block: int = 100

    def __post_init__(self) -> None:
        self.code.setdefault(c.IMPLEMENTATION.lower(), IMPLEMENTATION_CODE)

    def delegate(self, owner: str, target: str = c.IMPLEMENTATION) -> None:
        """Set a 7702 delegation."""
        self.code[owner.lower()] = bytes.fromhex("ef0100" + target[2:].lower())

    def handle(self, method: str, params: list[Any]) -> Any:
        """Answer one JSON-RPC call."""
        self.calls.append(method)
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getCode":
            return "0x" + self.code.get(params[0].lower(), b"").hex()
        if method == "eth_getBlockByNumber":
            return {"number": hex(self.block), "timestamp": hex(self.timestamp), "baseFeePerGas": hex(self.base_fee)}
        if method == "eth_getTransactionCount":
            return hex(self.nonces.get(params[0].lower(), 0))
        if method == "eth_getBalance":
            return hex(self.balances.get(params[0].lower(), 0))
        if method == "eth_gasPrice":
            return hex(self.gas_price)
        if method == "eth_estimateGas":
            if "authorizationList" in params[0] and not self.estimate_with_authorization:
                raise ValueError("authorizationList not supported")
            return hex(300_000)
        if method == "eth_sendRawTransaction":
            return self._execute(params[0])
        if method == "eth_getTransactionReceipt":
            return self.receipts.get(params[0].lower())
        if method == "eth_call":
            return self._call(params[0])
        if method == "eth_getStorageAt":
            return self._storage(params[0].lower(), params[1].lower())
        raise ValueError(f"unsupported {method}")

    def _storage(self, owner: str, slot: str) -> str:
        """Helix7702Account layout: ``grants`` at slot 0, ``policyGrants`` at slot 2."""
        for table, base in ((self.policy, 2), (self.session, 0)):
            for grant, key in table.get(owner, {}).items():
                if "0x" + keccak(bytes.fromhex(grant[2:]) + base.to_bytes(32, "big")).hex() == slot:
                    return "0x" + key[2:].lower().rjust(64, "0")
        return "0x" + "00" * 32

    def _call(self, call: dict[str, str]) -> str:
        owner, data = call["to"].lower(), call["data"].lower()
        grant = "0x" + data[10:]
        if self.code.get(owner, b"") != bytes.fromhex("ef0100" + c.IMPLEMENTATION[2:].lower()):
            return "0x"  # no Helix code runs at an account not delegated to it
        if data.startswith(c.selector("policyGrants(bytes32)")):
            key = self.policy.get(owner, {}).get(grant, c.ZERO)
            return "0x" + encode(["address", "bytes16", "uint48", "uint48", "uint32"], [key, bytes(16), 0, 0, 0]).hex()
        if data.startswith(c.selector("grants(bytes32)")):
            key = self.session.get(owner, {}).get(grant, c.ZERO)
            return "0x" + encode(["address", "address", "bytes32", "uint48", "uint48", "uint32"], [key, c.ZERO, bytes(32), 0, 0, 0]).hex()
        raise ValueError("unsupported eth_call")

    def _execute(self, raw: str) -> str:
        sender = Account.recover_transaction(raw).lower()
        tx = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
        assert tx["chainId"] == self.chain_id and tx["value"] == 0
        assert tx["nonce"] == self.nonces.get(sender, 0), "bad nonce"
        cost = tx["gas"] * tx["maxFeePerGas"]
        assert self.balances.get(sender, 0) >= cost, "insufficient balance"
        self.nonces[sender] = tx["nonce"] + 1
        record = {"type": tx["type"], "sender": sender, "tx": tx, "authorities": []}
        for entry in tx.get("authorizationList", ()):
            signer = authority(entry).lower()
            record["authorities"].append({"authority": signer, "nonce": entry["nonce"], "address": "0x" + bytes(entry["address"]).hex()})
            # EIP-7702: valid only when the nonce equals the authority's current nonce.
            if entry["chainId"] in (0, self.chain_id) and entry["nonce"] == self.nonces.get(signer, 0):
                self.delegate(signer, "0x" + bytes(entry["address"]).hex())
                self.nonces[signer] += 1
        self.sent.append(record)
        to = "0x" + bytes(tx["to"]).hex()
        data = "0x" + bytes(tx["data"]).hex()
        logs: list[dict[str, Any]] = []
        status = "0x1"
        delegated = self.code.get(to, b"") == bytes.fromhex("ef0100" + c.IMPLEMENTATION[2:].lower())
        if to == sender and delegated and data.startswith(c.INSTALL_SELECTOR):
            grant_id, grant, _ = decode(list(c.INSTALL_TYPES), bytes.fromhex(data[10:]))
            key = grant[0].lower()
            self.policy.setdefault(to, {})["0x" + grant_id.hex()] = key
            logs.append({"address": to, "topics": [c.POLICY_INSTALLED_TOPIC, "0x" + grant_id.hex(), "0x" + key[2:].rjust(64, "0")]})
        elif to == sender and delegated and data[:10] in c.REVOKE_SELECTORS.values():
            grant = "0x" + data[10:]
            table = self.policy if data[:10] == c.REVOKE_SELECTORS["policy"] else self.session
            table.setdefault(to, {}).pop(grant, None)
        elif to == sender and not delegated:
            pass  # a call to a plain EOA does nothing
        self.balances[sender] -= tx["gas"] * self.gas_price // 2
        self.block += 1
        tx_hash = "0x" + keccak(HexBytes(raw)).hex()
        self.receipts[tx_hash] = {
            "transactionHash": tx_hash,
            "status": status,
            "blockNumber": hex(self.block),
            "gasUsed": hex(tx["gas"] // 2),
            "from": sender,
            "to": to,
            "logs": logs,
            "type": hex(tx["type"]),
        }
        return tx_hash


@dataclass
class FakeSite:
    """The website's two public signer endpoints."""

    plans: dict[str, dict[str, Any]] = field(default_factory=dict)
    fetched: set[str] = field(default_factory=set)
    reports: list[tuple[str, str]] = field(default_factory=list)
    report_status: int = 200


def opener(chain: FakeChain, site: FakeSite):  # noqa: ANN201 - test transport.
    """Build an urlopen replacement routing RPC and website requests."""

    def open_(request, timeout):  # noqa: ANN001, ANN202
        url = request.full_url
        body = json.loads(request.data) if request.data else None
        parsed = urlparse(url)
        if url.rstrip("/") == RPC or parsed.path == "/rpc":
            try:
                result = chain.handle(body["method"], body["params"])
                answer = {"jsonrpc": "2.0", "id": body["id"], "result": result}
            except (ValueError, AssertionError) as error:
                answer = {"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": str(error)}}
            return _Response(json.dumps(answer).encode())
        parts = parsed.path.strip("/").split("/")
        if parts[:3] == ["api", "signer", "plans"]:
            token = parts[3]
            if len(parts) == 4 and request.get_method() == "GET":
                if token not in site.plans:
                    raise HTTPError(url, 404, "not found", {}, io.BytesIO(b'{"error": "unknown"}'))
                if token in site.fetched:
                    raise HTTPError(url, 410, "gone", {}, io.BytesIO(b'{"error": "used"}'))
                site.fetched.add(token)
                return _Response(json.dumps(site.plans[token]).encode())
            if len(parts) == 5 and parts[4] == "report":
                site.reports.append((token, body["txHash"]))
                if site.report_status != 200:
                    raise HTTPError(url, site.report_status, "no", {}, io.BytesIO(b'{"error": "rejected"}'))
                return _Response(b'{"ok": true, "status": "done"}')
        raise AssertionError(f"unexpected request {url}")

    return open_
