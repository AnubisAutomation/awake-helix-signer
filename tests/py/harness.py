"""Run a signer executable against the HTTP fakes, as a user would.

Used by ``test_cli.py`` (behaviour of the Rust CLI). Secrets are piped on stdin of a
process without a controlling terminal, exactly like the fork runner does.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from eth_account import Account

import fakes
from server import Fake

# The signer repository (works as a standalone clone and as a subdirectory).
ROOT = Path(__file__).resolve().parents[2]
RUST_BIN = Path(os.environ.get("HELIX_SIGNER_BIN") or ROOT / "target/release/awake-helix-signer")
DEVTOOL_BIN = Path(os.environ.get("HELIX_SIGNER_DEVTOOL") or RUST_BIN.with_name("helix-signer-devtool"))


def environment() -> dict[str, str]:
    """A fixed time zone and no stray Python warnings."""
    return {**os.environ, "TZ": "UTC", "PYTHONWARNINGS": "ignore", "AWAKE_HELIX_SIGNER_HOME": tempfile.gettempdir()}


class Run:
    """One finished run."""

    def __init__(self, completed: subprocess.CompletedProcess[str]) -> None:
        self.code = completed.returncode
        self.stdout = completed.stdout
        self.stderr = completed.stderr

    @property
    def text(self) -> str:
        return self.stdout + self.stderr

    def __repr__(self) -> str:
        return f"exit {self.code}\n--- stdout ---\n{self.stdout[-4000:]}\n--- stderr ---\n{self.stderr[-3000:]}"


def run(binary: Path, args: list[str], lines: list[str] | None = None, timeout: int = 180, env: dict[str, str] | None = None) -> Run:
    """Run the executable without a controlling terminal, secrets on stdin."""
    stdin = "".join(f"{line}\n" for line in lines or [])
    completed = subprocess.run(
        [str(binary), *args], input=stdin, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False, start_new_session=os.name == "posix", env=env or environment(),
    )
    return Run(completed)


class World:
    """A fake chain and website, an owner key and the signer arguments that reach them."""

    def __init__(self, folder: Path, account: Any = None) -> None:
        self.fake = Fake()
        self.folder = folder
        self.account = account or Account.create()
        self.owner = self.account.address
        self.chain = self.fake.chain
        self.site = self.fake.site
        self.backend = self.fake.backend
        self.chain.balances[self.owner.lower()] = 10**18
        self.chain.nonces[self.owner.lower()] = 3
        self.password = "keystore-pass-123"
        self.keystore = folder / "owner.json"
        self.keystore.write_text(json.dumps(Account.encrypt(self.account.key, self.password, kdf="pbkdf2", iterations=1000)))
        self.constants = folder / "dev-constants.json"
        self.constants.write_text(json.dumps(fakes.dev_constants()))
        self.private_key = self.account.key.hex().removeprefix("0x")

    @property
    def network(self) -> list[str]:
        """``--rpc`` and ``--dev-constants`` for the fakes (loopback, so dev constants are allowed)."""
        return ["--rpc", self.fake.rpc, "--dev-constants", str(self.constants)]

    @property
    def api(self) -> list[str]:
        return ["--api", self.fake.url]

    def close(self) -> None:
        self.fake.close()


class Background:
    """A long-running signer (``serve``) with its output collected."""

    def __init__(self, binary: Path, args: list[str], env: dict[str, str] | None = None) -> None:
        self.process = subprocess.Popen(
            [str(binary), *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=os.name == "posix", env=env or environment(),
        )
        self.lines: list[str] = []
        # Read what is printed as it comes: prompts end without a newline.
        self.reader = threading.Thread(target=lambda: self.lines.extend(iter(lambda: self.process.stdout.read1(4096).decode("utf-8", "replace"), "")), daemon=True)
        self.reader.start()

    def type(self, line: str) -> None:
        self.process.stdin.write((line + "\n").encode())
        self.process.stdin.flush()

    @property
    def output(self) -> str:
        return "".join(self.lines)

    def wait_for(self, fragment: str, seconds: float = 60) -> str:
        deadline = time.monotonic() + seconds
        while fragment not in self.output:
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise AssertionError(f"{fragment!r} not printed:\n{self.output[-3000:]}")
            time.sleep(0.05)
        return self.output

    def stop(self) -> None:
        try:
            os.killpg(self.process.pid, 15) if os.name == "posix" else self.process.terminate()
        except ProcessLookupError:
            pass
        self.process.wait(timeout=30)
        self.reader.join(timeout=5)
