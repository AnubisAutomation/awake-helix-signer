# Awake Helix Signer

The Awake Helix Signer authorizes and revokes the policy grants that let an
[Awake Helix](https://anubis.sivilization.com) bot act for your wallet on
Anubis Chain (chain ID 6714). Mainstream wallets refuse to sign an EIP-7702
delegation to a contract chosen by a website, so this small program does it on
your own device, after checking every value itself.

- `crates/helix-signer-core`: plan verification, keys, EIP-7702 signing, chain
  and website client, the local companion (API: [`API.md`](crates/helix-signer-core/API.md)).
- `crates/helix-signer-cli`: the `awake-helix-signer` command line.
- `app/`: the Tauri 2 app for Windows, macOS, Linux, Android and iOS (six
  languages, light and dark).

## Security model

- **Keys never leave the device.** A keystore, private key or mnemonic is read
  from a hidden prompt or password field, decrypted in memory and wiped after
  signing, on *Forget*, after 10 idle minutes and on exit. Nothing secret is
  sent, logged or written unless you save an encrypted keystore.
- **The website is not trusted.** A plan from the website is signed only when
  it matches constants compiled into the program
  ([`constants.rs`](crates/helix-signer-core/src/constants.rs)): chain 6714,
  the pinned EIP-7702 delegate and its runtime code hash, the EntryPoint, an
  allow-list of HELIX contracts and methods, and bounds on lifetime (90 days),
  call count and caps. The calldata is decoded and re-encoded byte for byte.
- **Session keys are attested.** Each bot's session key must carry an EIP-712
  attestation recovering to the platform attestation address pinned at build
  time ([`attestation_address.txt`](attestation_address.txt)); release builds
  refuse the placeholder.
- **What it signs:** one EIP-7702 type-4 transaction (delegation plus the
  `installPolicyGrant` self-call) or a plain self-call when already delegated
  to Helix, revocations (`revokePolicyGrant` / `revokeGrant`), and a
  `personal_sign` login message for the website's *My grants* list. Each
  authorization shows a summary decoded from the calldata and needs you to
  type `AUTHORIZE` (`REVOKE` for revocations).
- **Wrong chain or RPC is refused** (`eth_chainId`, delegate code hash), remote
  RPC and API must use HTTPS, and `awakehelix://` links naming another website
  are rejected. Use a dedicated bot wallet.

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Download

- Website: <https://anubis.sivilization.com/downloads/signer>
- GitHub Releases: <https://github.com/AnubisAutomation/awake-helix-signer/releases>

| System | File |
|---|---|
| Windows x64 | `awake-helix-signer-<version>-windows-x64-setup.exe` (CLI only: `-windows-x64-cli.exe`) |
| macOS (universal) | `awake-helix-signer-<version>-macos-universal.dmg` (CLI: `-macos-universal-cli.tar.gz`) |
| Linux x86_64 | `.deb` or `.AppImage` (CLI: `-linux-x86_64-cli.tar.gz`) |
| Android | `awake-helix-signer-<version>-android-universal.apk` |

Release files are built by GitHub Actions from the tagged commit
([`release.yml`](.github/workflows/release.yml)). iOS is not offered for
download; build it yourself on a Mac ([docs/BUILD.md](docs/BUILD.md)).

### Verify a download

Download `SHA256SUMS` from the same release next to the file, then:

```sh
sha256sum -c SHA256SUMS --ignore-missing          # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing      # macOS
```

```powershell
# Windows: the printed hash must equal the file's line in SHA256SUMS
Get-FileHash .\awake-helix-signer-0.5.1-windows-x64-setup.exe -Algorithm SHA256
```

Check that the file was built by this repository's release workflow
([GitHub artifact attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)):

```sh
gh attestation verify awake-helix-signer-0.5.1-windows-x64-setup.exe --repo AnubisAutomation/awake-helix-signer
```

The Windows installer is not code-signed and the macOS app is ad-hoc signed
(not notarized); see [First launch](docs/BUILD.md#first-launch).

## Build from source

Linux, Windows and Android build in containers (Docker with Buildx); macOS and
iOS build natively on a Mac with Xcode. One script does everything:

```sh
./build.sh linux --release        # .deb + AppImage + CLI tarball
./build.sh windows --release      # NSIS setup .exe + CLI .exe (cross-compiled)
./build.sh android --release      # signed universal APK
./build.sh macos --release        # on a Mac: .dmg + CLI
./build.sh all --release          # every platform this computer can build
```

On Windows use `.\build.ps1 all -Release` (Docker Desktop). Results go to
`dist/<platform>/` with a `.sha256` per file and `SHA256SUMS`. Every build
removes its caches when it ends (`--keep-cache` keeps them). Full guide:
[docs/BUILD.md](docs/BUILD.md).

Just the CLI with a local Rust toolchain (pinned in `rust-toolchain.toml`):

```sh
cargo build --release -p helix-signer-cli   # target/release/awake-helix-signer
```

## Tests

```sh
# Core and CLI: unit tests, known-answer vectors, in-process flows and companion,
# and the replay of the former Python signer's recorded answers
cargo clippy -p helix-signer-core -p helix-signer-cli --all-targets -- -D warnings
cargo test -p helix-signer-core -p helix-signer-cli

# The release CLI against the HTTP fakes of the website and chain (tests/py)
cargo build --release -p helix-signer-cli
uv run --no-project --python 3.12 --with eth-account==0.13.7 \
  python -m unittest discover -s tests/py -p 'test_*.py'

# Release tools (tools/release_manifest.py, tools/check_attestation_address.py)
uv run --no-project --python 3.12 --with eth-account==0.13.7 \
  python -m unittest discover -s tools -p 'test_*.py'

# The app: unit, frontend and desktop end-to-end tests (Linux container)
./build.sh test
```

Without uv, any Python 3.12 with `eth-account` works. `HELIX_SIGNER_BIN`
points the CLI tests at another binary. CI runs all of the above
([`ci.yml`](.github/workflows/ci.yml)).

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE). The BIP-39
wordlists come from the bitcoin/bips repository (MIT).
