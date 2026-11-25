"""Write or verify the signer downloads manifest (``manifest.json`` + ``SHA256SUMS``).

Usage::

    python3 -I tools/release_manifest.py write DIR --version 0.7.0 [--commit SHA]
    python3 -I tools/release_manifest.py verify DIR

``write`` lists every release file in DIR (the files ``build.sh
<platform> --release`` writes to ``dist/<platform>/``, collected in
one folder), derives os/arch/kind from the file name, and writes::

    {"schema": 1, "name": "anubisauto-signer", "version": "0.7.0",
     "commit": "<sha>", "files": [{"name", "os", "arch", "kind", "size", "sha256"}, ...]}

plus ``SHA256SUMS`` (``sha256sum -c`` format). The per-file ``<file>.sha256``
files and the build's own ``SHA256SUMS`` are skipped (``write`` replaces
``SHA256SUMS``). It refuses files of another version, ``-debug`` builds, the
team-signed iOS IPA (``-ios.ipa``: it installs only on the team's registered
devices) and any unknown name, so a stale or stray file never ships. The
unsigned iOS IPA (``-ios-unsigned.ipa``, a test build that SideStore or
AltStore re-sign with the user's Apple ID) is listed as ios/arm64/ipa. ``verify`` re-hashes every listed file and checks the sizes and
SHA256SUMS; it exits 1 on any mismatch. The Anubis Automation website's download page
(``/downloads/signer``) reads this manifest at runtime; its publishing step
runs ``write`` and ``verify``.
Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = 1
NAME = "anubisauto-signer"
SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
SHA = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.+-][0-9A-Za-z.]+)?$")
OSES = {"windows", "macos", "linux", "android", "ios"}
ARCHES = {"x86_64", "arm64", "universal"}
KINDS = {"installer", "dmg", "appimage", "deb", "apk", "ipa", "cli"}
# File name suffix -> (os, arch, kind). Windows "x64" is the usual name of x86_64.
PATTERNS = (
    ("-windows-x64-setup.exe", ("windows", "x86_64", "installer")),
    ("-windows-x64-cli.exe", ("windows", "x86_64", "cli")),
    *((f"-macos-{arch}.dmg", ("macos", arch, "dmg")) for arch in ("arm64", "x86_64", "universal")),
    *((f"-macos-{arch}-cli.tar.gz", ("macos", arch, "cli")) for arch in ("arm64", "x86_64", "universal")),
    *((f"-linux-{arch}.AppImage", ("linux", arch, "appimage")) for arch in ("x86_64", "arm64")),
    *((f"-linux-{arch}.deb", ("linux", arch, "deb")) for arch in ("x86_64", "arm64")),
    *((f"-linux-{arch}-cli.tar.gz", ("linux", arch, "cli")) for arch in ("x86_64", "arm64")),
    ("-android-universal.apk", ("android", "universal", "apk")),
    ("-ios-unsigned.ipa", ("ios", "arm64", "ipa")),
)
IGNORED = {"manifest.json", "SHA256SUMS"}


def sha256(path: Path) -> str:
    """SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def classify(name: str, version: str) -> tuple[str, str, str] | None:
    """(os, arch, kind) of a release file name, or None when it is not one."""
    for suffix, meaning in PATTERNS:
        if name == f"{NAME}-{version}{suffix}":
            return meaning
    return None


def write(folder: Path, version: str, commit: str = "") -> dict[str, object]:
    """Write ``manifest.json`` and ``SHA256SUMS`` for the files in ``folder``.

    Raises:
        SystemExit: A file of another version or unknown kind, or no files.
    """
    if not VERSION.match(version):
        raise SystemExit(f"invalid version {version!r}")
    if "debug" in version:
        raise SystemExit(f"{version}: a debug build (build.sh without --release) is never published")
    files = []
    for path in sorted(folder.iterdir()):
        if not path.is_file() or path.name in IGNORED or path.name.endswith((".sha256", ".txt")):
            continue
        meaning = classify(path.name, version)
        if meaning is None:
            raise SystemExit(f"{path.name}: not a release file of version {version}")
        os_name, arch, kind = meaning
        files.append({"name": path.name, "os": os_name, "arch": arch, "kind": kind,
                      "size": path.stat().st_size, "sha256": sha256(path)})
    if not files:
        raise SystemExit(f"no release files in {folder}")
    manifest: dict[str, object] = {"schema": SCHEMA, "name": NAME, "version": version, "commit": commit, "files": files}
    _replace(folder / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    _replace(folder / "SHA256SUMS", "".join(f"{item['sha256']}  {item['name']}\n" for item in files))
    return manifest


def _replace(path: Path, text: str) -> None:
    """Write a new file and rename it over ``path`` (never truncates a hard link)."""
    partial = path.with_name(f".{path.name}.partial")
    partial.write_text(text, encoding="utf-8", newline="\n")
    os.replace(partial, path)


def verify(folder: Path) -> list[str]:
    """Problems found in ``folder`` (empty when every file matches)."""
    try:
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"manifest.json: {error}"]
    problems: list[str] = []
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list) or not manifest["files"]:
        return ["manifest.json: no files"]
    if not VERSION.match(str(manifest.get("version", ""))):
        problems.append("manifest.json: invalid version")
    listed: dict[str, str] = {}
    for item in manifest["files"]:
        name = str(item.get("name", "")) if isinstance(item, dict) else ""
        if not SAFE.match(name) or "/" in name or "\\" in name or ".." in name:
            problems.append(f"unsafe file name {name!r}")
            continue
        if item.get("os") not in OSES or item.get("arch") not in ARCHES or item.get("kind") not in KINDS:
            problems.append(f"{name}: unknown os/arch/kind")
        if not SHA.match(str(item.get("sha256", ""))):
            problems.append(f"{name}: invalid sha256")
            continue
        path = folder / name
        if not path.is_file():
            problems.append(f"{name}: missing")
            continue
        if path.stat().st_size != item.get("size"):
            problems.append(f"{name}: size {path.stat().st_size} != {item.get('size')}")
        actual = sha256(path)
        if actual != item["sha256"]:
            problems.append(f"{name}: sha256 {actual} != {item['sha256']}")
        listed[name] = item["sha256"]
    sums = folder / "SHA256SUMS"
    if sums.is_file():
        for line in sums.read_text(encoding="utf-8").splitlines():
            digest, _, name = line.partition("  ")
            if listed.get(name) != digest:
                problems.append(f"SHA256SUMS: {name} does not match manifest.json")
    else:
        problems.append("SHA256SUMS: missing")
    return problems


def main(argv: list[str] | None = None) -> int:
    """Command line."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    written = commands.add_parser("write")
    written.add_argument("folder", type=Path)
    written.add_argument("--version", required=True)
    written.add_argument("--commit", default="")
    checked = commands.add_parser("verify")
    checked.add_argument("folder", type=Path)
    args = parser.parse_args(argv)
    if args.command == "write":
        manifest = write(args.folder, args.version, args.commit)
        print(json.dumps(manifest, indent=2))
        return 0
    problems = verify(args.folder)
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if not problems:
        print(f"ok: every file in {args.folder} matches manifest.json and SHA256SUMS")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
