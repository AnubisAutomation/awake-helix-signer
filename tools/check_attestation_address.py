"""Check attestation_address.txt before a signer release.

Usage::

    uv run --no-project --with eth-account==0.13.7 python -I tools/check_attestation_address.py [--release] [--expect 0xADDRESS]

Always checks that the file holds one checksummed, non-zero address. With
``--release`` the build placeholder is refused. ``--expect`` compares it with
the platform attestation address the Anubis Automation website publishes. Exits 0
when every check passes, 1 otherwise.
``build.sh`` (``check_attestation`` in ``build/scripts/common.sh``)
and the core's ``build.rs`` apply the same rules to every build; this tool
adds the ``--expect`` comparison. Needs ``eth-utils``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eth_utils import is_checksum_address

# The file every build pins, and the Rust core's constants (the source of truth).
SIGNER = Path(__file__).resolve().parents[1]
FILE = SIGNER / "attestation_address.txt"
CONSTANTS = SIGNER / "crates/helix-signer-core/src/constants.rs"


def placeholder() -> str:
    """Return ``ATTESTATION_PLACEHOLDER`` from the Rust constants source."""
    for line in CONSTANTS.read_text(encoding="utf-8").splitlines():
        if line.startswith("pub const ATTESTATION_PLACEHOLDER: &str = "):
            return line.split('"')[1]
    raise SystemExit("ATTESTATION_PLACEHOLDER not found in constants.rs")


def check(text: str, *, release: bool, expect: str | None) -> list[str]:
    """List everything wrong with the file's content.

    Args:
        text: str; file content.
        release: bool; whether the placeholder is refused.
        expect: str | None; address the file must equal.

    Returns:
        list[str]: Problems; empty when the file passes.
    """
    address = text.strip()
    if not is_checksum_address(address) or int(address, 16) == 0:
        return [f"{FILE.name} must hold one checksummed, non-zero address."]
    problems = []
    if release and address == placeholder():
        problems.append(
            f"{FILE.name} still holds the placeholder: set it to the platform attestation "
            "address the Anubis Automation website publishes before a release."
        )
    if expect is not None and address != expect:
        problems.append(f"{FILE.name} holds {address}, expected {expect}.")
    return problems


def main(argv: list[str] | None = None) -> int:
    """Run the checks.

    Args:
        argv: list[str] | None; command line.

    Returns:
        int: 0 when the file passes.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--release", action="store_true", help="Refuse the build placeholder.")
    parser.add_argument("--expect", help="Address the file must equal.")
    args = parser.parse_args(argv)
    if not FILE.is_file():
        print(f"{FILE} is missing.", file=sys.stderr)
        return 1
    problems = check(FILE.read_text(encoding="utf-8"), release=args.release, expect=args.expect)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"{FILE.name}: {FILE.read_text(encoding='utf-8').strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
