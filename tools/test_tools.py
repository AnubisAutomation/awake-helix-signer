"""Tests of the release tools (``release_manifest.py``, ``check_attestation_address.py``).

    uv run --no-project --with eth-account==0.13.7 python -m unittest discover -s tools -p 'test_*.py' -v

The attestation check needs ``eth-utils`` (e.g. from eth-account; skipped without it).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import release_manifest  # noqa: E402

VERSION = "1.2.3"
# Every name build.sh writes for a release (file suffix -> os, arch, kind).
RELEASE = {
    "linux-x86_64.AppImage": ("linux", "x86_64", "appimage"),
    "linux-x86_64.deb": ("linux", "x86_64", "deb"),
    "linux-x86_64-cli.tar.gz": ("linux", "x86_64", "cli"),
    "linux-arm64.AppImage": ("linux", "arm64", "appimage"),
    "linux-arm64.deb": ("linux", "arm64", "deb"),
    "linux-arm64-cli.tar.gz": ("linux", "arm64", "cli"),
    "windows-x64-setup.exe": ("windows", "x86_64", "installer"),
    "windows-x64-cli.exe": ("windows", "x86_64", "cli"),
    "android-universal.apk": ("android", "universal", "apk"),
    "macos-arm64.dmg": ("macos", "arm64", "dmg"),
    "macos-x86_64.dmg": ("macos", "x86_64", "dmg"),
    "macos-universal.dmg": ("macos", "universal", "dmg"),
    "macos-arm64-cli.tar.gz": ("macos", "arm64", "cli"),
    "macos-universal-cli.tar.gz": ("macos", "universal", "cli"),
}


def build_output(folder: Path, version: str = VERSION, suffixes: tuple[str, ...] = tuple(RELEASE)) -> None:
    """Release files as build.sh leaves them: each with <file>.sha256, plus SHA256SUMS."""
    lines = []
    for suffix in suffixes:
        name = f"anubisauto-signer-{version}-{suffix}"
        (folder / name).write_bytes(name.encode())
        line = f"{hashlib.sha256(name.encode()).hexdigest()}  {name}\n"
        (folder / f"{name}.sha256").write_text(line)
        lines.append(line)
    (folder / "SHA256SUMS").write_text("".join(lines))


class ReleaseManifestTests(unittest.TestCase):
    """Names, kinds and checksums of the published files."""

    def test_write_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            folder = Path(raw)
            build_output(folder)
            (folder / "notes.txt").write_text("ignored")
            manifest = release_manifest.write(folder, VERSION, commit="a" * 40)
            found = {item["name"].removeprefix(f"anubisauto-signer-{VERSION}-"): (item["os"], item["arch"], item["kind"])
                     for item in manifest["files"]}
            self.assertEqual(found, RELEASE)
            first = manifest["files"][0]
            self.assertEqual(first["sha256"], hashlib.sha256((folder / first["name"]).read_bytes()).hexdigest())
            self.assertEqual(first["size"], (folder / first["name"]).stat().st_size)
            self.assertEqual(json.loads((folder / "manifest.json").read_text()), manifest)
            self.assertEqual(len((folder / "SHA256SUMS").read_text().splitlines()), len(RELEASE))
            self.assertEqual(release_manifest.verify(folder), [])
            # The manifest and SHA256SUMS agree with the build's own .sha256 files.
            for item in manifest["files"]:
                self.assertEqual((folder / f"{item['name']}.sha256").read_text().split()[0], item["sha256"])
            (folder / manifest["files"][2]["name"]).write_bytes(b"tampered")
            problems = release_manifest.verify(folder)
            self.assertTrue(any("sha256" in problem and manifest["files"][2]["name"] in problem for problem in problems), problems)

    def test_lists_the_unsigned_ios_ipa(self) -> None:
        # The SideStore/AltStore test build is published as ios/arm64/ipa.
        with tempfile.TemporaryDirectory() as raw:
            folder = Path(raw)
            build_output(folder, suffixes=("linux-x86_64.deb", "ios-unsigned.ipa"))
            manifest = release_manifest.write(folder, VERSION)
            ios = [item for item in manifest["files"] if item["os"] == "ios"]
            self.assertEqual([(item["name"], item["arch"], item["kind"]) for item in ios],
                             [(f"anubisauto-signer-{VERSION}-ios-unsigned.ipa", "arm64", "ipa")])
            self.assertEqual(release_manifest.verify(folder), [])

    def test_refuses_other_versions_debug_builds_signed_ios_and_unknown_files(self) -> None:
        for extra in (
            f"anubisauto-signer-1.2.2-linux-x86_64.deb",
            f"anubisauto-signer-{VERSION}-debug-linux-x86_64.deb",
            f"anubisauto-signer-{VERSION}-ios.ipa",
            f"anubisauto-signer-{VERSION}-solaris-sparc.bin",
            f"awake_helix_signer-{VERSION}-py3-none-any.whl",
            f"anubisauto-signer-{VERSION}-windows-x64.zip",
        ):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as raw:
                folder = Path(raw)
                build_output(folder, suffixes=("linux-x86_64.deb",))
                (folder / extra).write_bytes(b"x")
                with self.assertRaises(SystemExit):
                    release_manifest.write(folder, VERSION)
        with tempfile.TemporaryDirectory() as raw, self.assertRaises(SystemExit):
            release_manifest.write(Path(raw), VERSION)
        with tempfile.TemporaryDirectory() as raw:
            build_output(Path(raw), f"{VERSION}-debug", ("linux-x86_64.deb",))
            with self.assertRaises(SystemExit):
                release_manifest.write(Path(raw), f"{VERSION}-debug")

    def test_verify_rejects_path_names_and_unknown_kinds(self) -> None:
        for item in (
            {"name": "../etc/passwd", "os": "linux", "arch": "x86_64", "kind": "deb", "size": 1, "sha256": "0" * 64},
            {"name": "x.whl", "os": "any", "arch": "any", "kind": "wheel", "size": 1, "sha256": "0" * 64},
        ):
            with self.subTest(item=item), tempfile.TemporaryDirectory() as raw:
                folder = Path(raw)
                (folder / "manifest.json").write_text(json.dumps({"version": "1.0.0", "files": [item]}))
                self.assertTrue(release_manifest.verify(folder))

    def test_cli(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            build_output(Path(raw))
            tool = TOOLS / "release_manifest.py"
            subprocess.run([sys.executable, "-I", str(tool), "write", raw, "--version", VERSION], check=True, capture_output=True)
            checked = subprocess.run([sys.executable, "-I", str(tool), "verify", raw], capture_output=True, text=True, check=False)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            (Path(raw) / f"anubisauto-signer-{VERSION}-android-universal.apk").write_bytes(b"other")
            checked = subprocess.run([sys.executable, "-I", str(tool), "verify", raw], capture_output=True, text=True, check=False)
            self.assertEqual(checked.returncode, 1)


@unittest.skipUnless(importlib.util.find_spec("eth_utils"), "needs eth-utils (uv run --with eth-account==0.13.7 ...)")
class AttestationCheckTests(unittest.TestCase):
    """check_attestation_address.py reads the Rust core's placeholder."""

    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("check_attestation_address", TOOLS / "check_attestation_address.py")
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)

    def test_release_check(self) -> None:
        placeholder = self.tool.placeholder()
        self.assertRegex(placeholder, r"^0x[0-9a-fA-F]{40}$")
        good = "0xA9BeE92e6C1d43B162D799883E4401485C9a3334"
        other = "0x9F0b8B2d2D7eFB697742B05b0E081E8e87B061DC"
        self.assertEqual(self.tool.check(f"{good}\n", release=True, expect=None), [])
        self.assertEqual(self.tool.check(good, release=True, expect=good), [])
        self.assertEqual(self.tool.check(placeholder, release=False, expect=None), [])
        self.assertIn("placeholder", self.tool.check(placeholder, release=True, expect=None)[0])
        self.assertIn("expected", self.tool.check(good, release=True, expect=other)[0])
        for bad in ("", "nope", "0x" + "00" * 20, good.lower()):
            with self.subTest(bad=bad):
                self.assertTrue(self.tool.check(bad, release=False, expect=None))

    def test_the_committed_file_passes(self) -> None:
        self.assertEqual(self.tool.main([]), 0)


if __name__ == "__main__":
    unittest.main()
