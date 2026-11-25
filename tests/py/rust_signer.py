"""The Rust signer's checks for Python tests (the Anubis Automation website's tests).

A thin adapter over ``helix-signer-devtool batch`` with the names the Python
signer's library had, for tests that verify website output with it (the
Anubis Automation website's): the same refusals, the same decoded
values, from the code users run.

    from rust_signer import PlanError, verify_grant_plan
    verified = verify_grant_plan(plan, {"implementation": ..., "attestationAddress": ...})
    verified.remaining_calls, verified.rules[0].max_amount, verified.summary

``constants`` is None or ``"production"`` for the pinned constants, or a
``--dev-constants`` document (``pinned_with(attestationAddress=...)`` builds
one from the pinned values). A development document only changes the values
it names; plan verification ignores the ``development`` flag (it only labels
summaries).

``cli(args, lines)`` runs the user-facing ``anubisauto-signer`` executable
without a controlling terminal, secrets on stdin, as a user's script would.

``HELIX_SIGNER_DEVTOOL`` names the devtool (default
``target/release/helix-signer-devtool`` in this repository), ``HELIX_SIGNER_BIN``
the CLI (default ``target/release/anubisauto-signer``). A missing
binary raises ``SignerMissing`` saying how to build it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

# The signer repository (works as a standalone clone and as a subdirectory).
ROOT = Path(__file__).resolve().parents[2]
DEVTOOL = Path(os.environ.get("HELIX_SIGNER_DEVTOOL") or ROOT / "target/release/helix-signer-devtool")
BIN = Path(os.environ.get("HELIX_SIGNER_BIN") or ROOT / "target/release/anubisauto-signer")
BUILD = f"cd {ROOT} && cargo build --release -p helix-signer-cli"


class SignerMissing(RuntimeError):
    """The Rust signer binary is not built (or the override names nothing)."""


class SignerError(ValueError):
    """The Rust signer refused; ``kind`` is its error kind (``plan``, ``login``, ...)."""

    def __init__(self, message: str, kind: str = "") -> None:
        super().__init__(message)
        self.kind = kind


class PlanError(SignerError):
    """The plan does not match what the signer is willing to sign."""


class LoginError(SignerError):
    """The website sign-in was refused (for example a foreign challenge)."""


def require(binary: Path, variable: str) -> Path:
    """The binary, or SignerMissing telling how to build it."""
    if not (binary.is_file() and os.access(binary, os.X_OK)):
        raise SignerMissing(f"Rust signer binary {binary} is missing; run `{BUILD}` (or set {variable}).")
    return binary


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _namespace(value: Any) -> Any:
    if isinstance(value, dict):
        return SimpleNamespace(**{_snake(key): (item if key == "plan" else _namespace(item)) for key, item in value.items()})
    if isinstance(value, list):
        return [_namespace(item) for item in value]
    return value


def run(*operations: dict[str, Any]) -> list[dict[str, Any]]:
    """Run operations through the devtool; one ``{"ok": ...}`` or ``{"error": ...}`` each."""
    lines = "".join(json.dumps(operation) + "\n" for operation in operations)
    completed = subprocess.run([str(require(DEVTOOL, "HELIX_SIGNER_DEVTOOL")), "batch"], input=lines, capture_output=True, text=True, check=True, timeout=120)
    return [json.loads(line) for line in completed.stdout.splitlines()]


def _one(operation: dict[str, Any]) -> Any:
    (answer,) = run(operation)
    if "error" in answer:
        kind = answer.get("kind", "")
        error = {"plan": PlanError, "login": LoginError}.get(kind, SignerError)
        raise error(answer["error"], kind)
    return answer["ok"]


def verify_grant_plan(plan: Any, constants: dict[str, Any] | str | None = None, now: int | None = None) -> SimpleNamespace:
    """Verify a grant plan; ``constants`` is a ``--dev-constants`` document or None (production)."""
    answer = _one({"op": "verify_grant", "plan": plan, "constants": constants, "now": now, "rpc": "", "api": None})
    verified = _namespace(answer["plan"])
    for rule in verified.rules:
        for field in ("max_amount", "max_secondary", "max_daily", "min_out_per_in_wad"):
            setattr(rule, field, int(getattr(rule, field)))
    verified.summary = answer["summary"]
    return verified


def verify_revoke_plan(plan: Any, constants: dict[str, Any] | str | None = None, state: str | None = None) -> SimpleNamespace:
    """Verify a revocation plan; ``state`` (``"v1"``, ``"v2"`` or ``"plain"``) also binds it to the wallet's Diamond."""
    operation = {"op": "verify_revoke", "plan": plan, "constants": constants, "rpc": "", "api": None}
    if state is not None:
        operation["state"] = state
    answer = _one(operation)
    verified = _namespace(answer["plan"])
    verified.summary = answer["summary"]
    return verified


def revoke_call_accepted(call: dict[str, Any], owner: str, grant_id: str) -> bool:
    """Whether ``grants revoke`` would sign this website-built revocation call."""
    return "ok" in run({"op": "revoke_call", "call": call, "owner": owner, "grant": grant_id, "constants": "production"})[0]


def check_challenge(message: Any, owner: str, api: str) -> str:
    """The domain of an acceptable sign-in message, else LoginError."""
    return _one({"op": "check_challenge", "message": message, "owner": owner, "api": api})


def constants(spec: dict[str, Any] | str | None = None) -> dict[str, Any]:
    """The pinned (or development) constants and the rule allow-list."""
    return _one({"op": "dev_constants", "constants": spec})


PINNED_FIELDS = (
    "implementation", "implementationCodeHash", "implementationV1", "implementationV1CodeHash", "entryPoint",
    "legacySessionKey", "attestationAddress",
)


def pinned_with(**changes: str) -> dict[str, Any]:
    """A ``--dev-constants`` document: the pinned values with ``changes`` (camelCase names)."""
    pinned = constants()
    unknown = set(changes) - set(PINNED_FIELDS)
    if unknown:
        raise ValueError(f"not a dev-constants field: {sorted(unknown)}")
    return {**{name: pinned[name] for name in PINNED_FIELDS}, **changes}


def cli(args: list[str], lines: list[str] | None = None, *, env: dict[str, str] | None = None,
        timeout: int = 180) -> subprocess.CompletedProcess[str]:
    """Run ``anubisauto-signer`` without a controlling terminal, ``lines`` on stdin."""
    binary = require(BIN, "HELIX_SIGNER_BIN")
    return subprocess.run(
        [str(binary), *args], input="".join(f"{line}\n" for line in lines or []), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout, check=False,
        start_new_session=os.name == "posix", env={"TZ": "UTC", **(env if env is not None else os.environ)},
    )
