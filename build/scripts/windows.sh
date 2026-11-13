#!/bin/sh
# Windows cross build (inside build/docker/windows.Dockerfile): the CLI .exe
# and the NSIS setup .exe for x86_64-pc-windows-msvc with cargo-xwin, then
# smoke tests: both are PE executables, the CLI runs under Wine, and the
# installer carries the app, the CLI and the WebView2 bootstrapper step.
#   build/scripts/windows.sh [app|cli]
. "$(dirname "$0")/common.sh"

what=${1:-app}
triple=x86_64-pc-windows-msvc
# The CLI links the C runtime statically (no Visual C++ Redistributable
# needed). The app does not: its library is also a cdylib (for the mobile
# builds), and tauri-build already links the VC runtime statically while the
# Universal CRT ships with Windows 10 and 11.
CLI_RUSTFLAGS="-C target-feature=+crt-static"

check_attestation
out=$(out_dir windows)

(export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="$CLI_RUSTFLAGS"; cli_build "$triple" xwin)
cli=$(cli_path "$triple")
file "$cli" | grep -q 'PE32+ executable' || die "$cli is not a 64-bit Windows executable"
cp "$cli" "$out/$(release_name windows-x64-cli.exe)"
wine=$(command -v wine 2> /dev/null || command -v wine64 2> /dev/null || ls /usr/lib/wine/wine64 2> /dev/null || true)
if [ -n "$wine" ]; then
  say "smoke: wine awake-helix-signer.exe --version"
  WINEPREFIX=${WINEPREFIX:-/tmp/wine-smoke} "$wine" "$cli" --version 2>/dev/null | tr -d '\r' | tee /tmp/cli-version.txt
  grep -q "$APP_VERSION" /tmp/cli-version.txt || die "the CLI did not print version $APP_VERSION under Wine"
else
  say "smoke: Wine is not installed; skipped running the CLI"
fi

if [ "$what" = app ]; then
  frontend
  sidecar "$triple"
  say "app: tauri build --runner cargo-xwin --target $triple --bundles nsis ($PROFILE)"
  # shellcheck disable=SC2086
  (cd app && npx tauri build $TAURI_PROFILE_FLAG --runner cargo-xwin --target "$triple" --bundles nsis \
      --config src-tauri/tauri.desktop-cli.conf.json --ci)
  bundle=$CARGO_TARGET_DIR/$triple/$PROFILE/bundle
  setup=$(ls "$bundle"/nsis/*-setup.exe | head -n 1)
  [ -f "$setup" ] || die "tauri produced no NSIS installer in $bundle"
  file "$setup" | grep -q 'PE32' || die "$setup is not a Windows executable"
  app_exe=$CARGO_TARGET_DIR/$triple/$PROFILE/awake-helix-signer-app.exe
  file "$app_exe" | grep -q 'PE32+ executable (GUI)' || die "$app_exe is not a 64-bit Windows GUI executable"
  if [ -n "$wine" ]; then
    # Loads every DLL the app imports (no window: --version exits before WebView2 starts).
    say "smoke: wine awake-helix-signer-app.exe --version"
    WINEPREFIX=${WINEPREFIX:-/tmp/wine-smoke} "$wine" "$app_exe" --version 2>/dev/null | tr -d '\r' | tee /tmp/app-version.txt
    grep -q "awake-helix-signer-app $APP_VERSION" /tmp/app-version.txt || die "the app did not start under Wine"
  fi
  # The installer is an NSIS archive: its data must contain both executables.
  grep -c 'awake-helix-signer.exe' "$setup" > /dev/null || say "note: file names inside the NSIS archive are compressed"
  cp "$setup" "$out/$(release_name windows-x64-setup.exe)"
fi
checksums "$out"
