# Build the CLI and the apps

One core library (`crates/helix-signer-core`: plan verification against pinned constants, keys, EIP-7702 signing, chain, website login, install check) is used by the `awake-helix-signer` command line (`crates/helix-signer-cli`) and by the **Awake Helix Signer** app (`app/`, Tauri 2) for Windows, macOS, Linux, Android and iOS. The app has three pages — **Request** (opened by `awakehelix://sign|revoke|ping|grants` links or a pasted token: load the key, read the summary decoded from the calldata, edit expiry/calls/caps, type `AUTHORIZE`), **My grants** (sign in with a local signature, list, revoke selected / all after typing `REVOKE`) and **This computer** — in six languages (繁體中文, 简体中文, English, 日本語, 한국어, Español; the OS language by default) with light/dark themes. Keys stay in memory only (wiped after signing, on Forget and after 10 idle minutes) unless you save an encrypted keystore. Phones get the same app without the companion `serve` and without a command-line tool; iOS has only a test build (the unsigned IPA below, installed with SideStore or AltStore).

One script builds everything: `build.sh` (POSIX shell; `build.ps1` does the same from PowerShell with Docker Desktop on Windows). Linux, Windows and Android are built **in containers**; macOS and iOS only natively on a Mac, because Xcode and Apple's SDKs cannot run in a container. The script only uses this repository (mounted at `/src` in the containers), so it works the same in a standalone clone and when the repository is checked out inside another one (e.g. as a git submodule: `./signer-rs/build.sh …`).

Official releases are built by GitHub Actions ([`release.yml`](../.github/workflows/release.yml)) with the same script; see *Releases* below.

## Quick start: build every app

1. Install and start Docker (Docker Engine on Linux, Docker Desktop on Windows/macOS). On a Mac, also install Xcode, rustup and Node 24 (see *Prerequisites*).
2. Clone the repository (on Windows first run `git config --global core.autocrlf false`).
3. If you already have the Android signing key, copy the folder `~/.awake-helix-signing/` to the same place on this computer **before** building; otherwise the first build creates a new key there (back it up, see below).
4. From the repository root, build everything this computer can:

   ```sh
   ./build.sh all --release              # Linux or macOS host
   ```

   ```powershell
   .\build.ps1 all -Release              # Windows host (PowerShell, Docker Desktop)
   ```

   `all` starts one container after the other and builds **Linux** (.deb, AppImage, CLI), **Windows** (setup .exe, CLI .exe, cross-compiled) and **Android** (signed APK). On a Mac it then also builds **macOS** (.dmg + CLI) natively, and **iOS** (signed) when `APPLE_DEVELOPMENT_TEAM` is set; for the unsigned SideStore/AltStore IPA run `./build.sh ios --release` on its own. Each run downloads and builds the container images and tools (allow ~30–60 min and ~25 GB of free disk while it runs), because the script **removes all its caches when it ends** (see *Cleanup after every build*); add `--keep-cache` to keep them and make the next run much faster. On Apple Silicon Macs the x86_64 containers run under emulation and are noticeably slower.
5. The results are in `dist/linux`, `dist/windows`, `dist/android` (and `dist/macos`); the script prints the list of files at the end.

To build only one platform, use its name instead of `all` (`linux`, `windows`, `android`, `macos`, `ios`); all options are under *Commands* and in `./build.sh --help`.

## Prerequisites

| Host | Needs |
|---|---|
| Linux | Docker Engine with the Buildx plugin (`docker-buildx-plugin`; ≈ 25 GB free disk while building, freed again at the end); `/dev/kvm` optional (Android emulator smoke test) |
| Windows | Docker Desktop with Linux containers; PowerShell 5+; `git config core.autocrlf false` before cloning (the build scripts must keep LF endings) |
| macOS (for `linux`/`windows`/`android`) | Docker Desktop |
| macOS (for `macos`/`ios`) | Xcode (App Store; `sudo xcode-select -s /Applications/Xcode.app`), rustup (the toolchain is pinned in `rust-toolchain.toml` and installed automatically), Node 24 (pinned `24.22.2`); for a universal macOS build `rustup target add aarch64-apple-darwin x86_64-apple-darwin`; for iOS also `brew install xcodegen cocoapods` and an Apple ID in Xcode |

Pinned versions: `rust-toolchain.toml` (Rust), `build/versions.env` (Node, rustup, cargo-xwin, tauri-driver, Android command-line tools, platforms android-36 and android-37.0, build-tools 36.0.0, NDK 28.2.13676358, the emulator system image, Python for the test fakes, the BuildKit image), `app/package-lock.json` (Tauri CLI 2.12.4, Vite, Vitest) and `Cargo.lock` (crates; enforced with `--locked` in `--release` builds). Every build first checks that `attestation_address.txt` holds the release attestation address and refuses the placeholder.

## Commands

```sh
./build.sh linux --release          # .deb + AppImage + CLI tarball (x86_64; --arch arm64 under QEMU/buildx)
./build.sh windows --release        # NSIS setup .exe + CLI .exe (cross-compiled with cargo-xwin)
./build.sh android --release        # signed universal APK (arm64-v8a + x86_64)
./build.sh all --release            # every platform this computer can build (see Quick start)
./build.sh all-linux-host --release # linux, windows and android only (also on a Mac)
./build.sh cli-linux --release      # only the Linux CLI tarball
./build.sh cli-windows --release    # only the Windows CLI .exe
./build.sh macos --release          # on a Mac: .app in a .dmg (host CPU, or universal), ad-hoc signed
./build.sh ios --release                                     # on a Mac: unsigned IPA for SideStore/AltStore
APPLE_DEVELOPMENT_TEAM=ABCDE12345 ./build.sh ios --release   # on a Mac: IPA signed for your registered devices (run in Terminal, not over SSH)
./build.sh test                     # app unit tests, frontend tests and the desktop end-to-end test
./build.sh images                   # only prepare the three build images
./build.sh clean                    # remove caches kept by an earlier --keep-cache build
```

On Windows: `.\build.ps1 windows -Release` or `.\build.ps1 all -Release` (same platforms; `-Out DIR`, `-KeepCache`, `-NoEmulator`). Without `--release` a faster debug build is made and every file name carries `-debug` (never published). `--out DIR` writes somewhere else. `android` also boots an emulator and installs the APK when `/dev/kvm` is usable (`--emulator` forces it, `--no-emulator` skips it); `test` runs a subset with `HELIX_TEST_PARTS="frontend rust e2e"`. `./build.sh --help` prints the full usage and environment (`HELIX_ANDROID_KEYSTORE*`, `HELIX_MIN_FREE_GB`, `HELIX_WAIT_MAX`, `HELIX_KEEP_CACHE`, `APPLE_DEVELOPMENT_TEAM`). The script runs one heavy build at a time (lock in `/tmp`), waits while the machine is loaded, stops when free disk would drop below 10 GB (`HELIX_MIN_FREE_GB`), and during the build keeps cargo, npm, Gradle and tool downloads in named Docker volumes (`awake-helix-signer-*`).

Outputs go to `dist/<platform>/` (never committed), each file with a `<file>.sha256` and the directory's `SHA256SUMS`:

| Platform | Files |
|---|---|
| linux | `awake-helix-signer-0.5.2-linux-x86_64.AppImage`, `awake-helix-signer-0.5.2-linux-x86_64.deb`, `awake-helix-signer-0.5.2-linux-x86_64-cli.tar.gz` |
| windows | `awake-helix-signer-0.5.2-windows-x64-setup.exe`, `awake-helix-signer-0.5.2-windows-x64-cli.exe` |
| android | `awake-helix-signer-0.5.2-android-universal.apk` |
| macos | `awake-helix-signer-0.5.2-macos-arm64.dmg` (or `-x86_64` / `-universal`), `awake-helix-signer-0.5.2-macos-<arch>-cli.tar.gz` |
| ios | `awake-helix-signer-0.5.2-ios-unsigned.ipa` (for SideStore/AltStore), or `awake-helix-signer-0.5.2-ios.ipa` with `APPLE_DEVELOPMENT_TEAM`; only the unsigned IPA can be published (as a test build, `ios/arm64/ipa` in the manifest) |

Each build smoke-tests what it made: Linux runs the CLI, checks the `.deb` (CLI in `/usr/bin`, `x-scheme-handler/awakehelix` in the desktop file) and runs the app's `--selftest` (the real WebKitGTK window renders every page in every language and opens sample links through the core) under Xvfb from both the `.deb` layout and the AppImage; Windows runs the CLI `.exe` under Wine and checks both executables; Android verifies the APK with `apksigner` and `aapt2` (package, version, both ABIs, the `awakehelix://` BROWSABLE intent filter) and, when `/dev/kvm` works, boots an emulator, installs the APK and opens `awakehelix://grants` with it; macOS verifies the ad-hoc signature, the URL scheme and runs `--selftest`.

The app registers `awakehelix://` everywhere: the Windows installer and the `.deb` at install, macOS through the bundle's `Info.plist`, Android through an intent filter and iOS through a URL type; the AppImage asks once on first start (or use **Register awakehelix:// links** on *This computer*). A link clicked while the desktop app runs is handed to the open window (single instance). The Windows installer puts the CLI next to the app and on the user's `PATH`; the `.deb` installs `/usr/bin/awake-helix-signer`; the AppImage and macOS app offer **Install command-line tool** (`~/.local/bin`, or `/usr/local/bin` on macOS).

## Cleanup after every build

When a build ends — successfully or not, also after Ctrl+C — `build.sh` and `build.ps1` remove everything the build created, so nothing is left on the computer except the results:

| Removed | Kept |
|---|---|
| this script's Docker images (`awake-helix-signer-build-*`) and any leftover build containers | `dist/<platform>/` (the release files, `.sha256`, `SHA256SUMS`) |
| its named volumes (`awake-helix-signer-*`: cargo registry and targets, npm, Gradle, Android SDK tools, emulator) | the Android signing key (`~/.awake-helix-signing/`) |
| its own BuildKit builder `awake-helix-signer` with its build cache, and the pinned `moby/buildkit` image when no container uses it | other Docker images, volumes and build caches on the computer (never pruned) |
| generated files in `app/`: `dist`, `src-tauri/gen` (Android/Xcode projects), `src-tauri/binaries`, `src-tauri/icons`, `src-tauri/app-icon.png` | your own `~/.cargo`, `~/.npm`, `~/.rustup`, Xcode, Node and Docker installs |
| on a Mac: the build's cargo/npm caches and target dir in `.build-cache/`, `app/node_modules`, and the build's Xcode DerivedData | |

The images are built with a dedicated BuildKit builder (`docker buildx`, included in Docker Desktop; on Linux the `docker-buildx-plugin` package) so its cache can be removed without touching anyone else's. The price is that every build starts from scratch. To iterate faster, add `--keep-cache` (PowerShell: `-KeepCache`, or `HELIX_KEEP_CACHE=1`); the caches then stay until a later build without it, or `./build.sh clean`, removes them. The script prints the free disk space before and after the cleanup.

## Android signing key — back it up

The first `android` build creates the release signing key **outside the repository**: `~/.awake-helix-signing/android-release.jks` plus its random password in `~/.awake-helix-signing/android-release.password` (directory 0700, files 0600), and prints a loud reminder. **Back both up offline right away.** Every update of the app must be signed with the same key; if it is lost, phones that installed the app can only uninstall it and install a new one. Never commit or upload it. Use another key with `HELIX_ANDROID_KEYSTORE=/path/key.jks HELIX_ANDROID_KEYSTORE_PASSWORD_FILE=/path/key.password HELIX_ANDROID_KEY_ALIAS=alias` (PKCS12, store and key password equal). The script refuses a keystore inside this repository (or inside a repository it is checked out in).

The folder is created on **the computer that runs the first `android` build**, in the home directory of the user who ran it (`/root/.awake-helix-signing/` when run as root; `C:\Users\<you>\.awake-helix-signing\` on Windows). Its name starts with a dot, so `ls` shows it only with `ls -a`, and only its owner can read it. Before building on another computer, copy the folder there (same path, directory 0700, files 0600) — or, as long as no one has installed the app yet, let that computer create a new key and use it from then on.

For the release workflow the same key is stored as repository secrets (see *Releases*): `base64 -w0 android-release.jks` gives `ANDROID_KEYSTORE_BASE64`, the content of `android-release.password` is `ANDROID_KEYSTORE_PASSWORD`.

## First launch

- **Windows**: the installer is not code-signed yet, so SmartScreen says "Windows protected your PC": choose *More info* → *Run anyway* after checking the file's SHA-256. The installer installs for the current user and downloads Microsoft's WebView2 runtime if it is missing (internet needed once).
- **macOS**: the app is ad-hoc signed, not notarized: open the `.dmg`, drag the app to *Applications*, then right-click it → *Open* → *Open* (or *System Settings → Privacy & Security → Open Anyway*). Run it from *Applications* so links open it.
- **Linux**: `sudo apt install ./awake-helix-signer-0.5.2-linux-x86_64.deb`, or `chmod +x` the AppImage and run it (it asks once whether to register links and add the terminal command).
- **Android**: check the APK's SHA-256 against `SHA256SUMS` (or the download page), allow *Install unknown apps* for the browser or file manager that opens the APK (Settings → Apps → Special access), install, and turn the permission off again. Links from the website in the phone's browser then open the app; keystore files are imported with the file picker.
- **iOS** (test build; not built by GitHub Actions, so no build provenance):
  - **Unsigned IPA (default) with SideStore or AltStore**: download `awake-helix-signer-0.5.2-ios-unsigned.ipa` on the iPhone (from the website, or AirDrop/Files) and open it with SideStore/AltStore (*My Apps → +*). It signs the app with your Apple ID while installing and refreshes it before it expires (7 days with a free Apple ID). Links from the website (`awakehelix://`) then open the app.
  - **Signed IPA** (`APPLE_DEVELOPMENT_TEAM` set): build in Terminal on the Mac itself — over SSH `codesign` cannot use the login keychain (`errSecInternalComponent`). Install it from Xcode (*Window → Devices and Simulators*), then *Settings → General → VPN & Device Management → Developer App → Trust*.
  - The iOS build needs iOS 15 or later; it also needs `brew install xcodegen cocoapods` on the Mac.

## Releases

A pushed tag `vX.Y.Z` (or a manual run of the *Release* workflow with an existing tag) builds every platform on GitHub-hosted runners and publishes the GitHub Release:

1. `meta` refuses a tag that does not match the version in `Cargo.toml`, `app/package.json` and `app/src-tauri/tauri.conf.json`.
2. `linux`, `windows` (both on `ubuntu-latest`, `./build.sh <platform> --release`), `android` (`./build.sh android --release --no-emulator`, only when the secrets `ANDROID_KEYSTORE_BASE64` and `ANDROID_KEYSTORE_PASSWORD` exist; optional `ANDROID_KEY_ALIAS`, default `awake-helix-signer`) and `macos` (`./build.sh macos --release` on an Apple Silicon runner with both Rust targets: a universal `.dmg`).
3. `release` checks every `.sha256`, writes one `SHA256SUMS` and `manifest.json` (`tools/release_manifest.py`: it refuses `-debug` builds, other versions and unknown names), attests the build provenance of every file and creates or updates the release with the notes (files, sizes, SHA-256, how to verify). Without the Android secrets the release says that Android is missing.

To publish a new version: raise `version` in `Cargo.toml` (`[workspace.package]`), `app/package.json` (and `app/package-lock.json`) and `app/src-tauri/tauri.conf.json`, commit, then `git tag v<version> && git push origin v<version>`.

Local builds (`./build.sh all --release`) produce the same file names; the published files are the ones the workflow built (verify them with `gh attestation verify <file> --repo AnubisAutomation/awake-helix-signer`).

## Tests

`cargo test -p helix-signer-core -p helix-signer-cli` and `cargo clippy -p helix-signer-core -p helix-signer-cli --all-targets -- -D warnings`, the CLI against HTTP fakes (`uv run --no-project --python 3.12 --with eth-account==0.13.7 python -m unittest discover -s tests/py -p 'test_*.py'`, after `cargo build --release -p helix-signer-cli`), the release tools (the same with `-s tools`) and `./build.sh test` for the app; see the [README](../README.md#tests).
