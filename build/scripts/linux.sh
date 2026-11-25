#!/bin/sh
# Linux build (inside build/docker/linux.Dockerfile): the CLI, the .deb and
# the AppImage, then smoke tests: the CLI runs, the .deb and the AppImage
# contain the app, the CLI and the anubisauto:// (and legacy awakehelix://)
# handler, and the app's
# --selftest passes under Xvfb (the real webview loads the page, renders
# every page in every language and opens sample links through the core).
#   build/scripts/linux.sh [app|cli]
. "$(dirname "$0")/common.sh"

what=${1:-app}
case $(uname -m) in
  x86_64) triple=x86_64-unknown-linux-gnu; arch=x86_64; deb_arch=amd64 ;;
  aarch64) triple=aarch64-unknown-linux-gnu; arch=arm64; deb_arch=arm64 ;;
  *) die "unsupported CPU $(uname -m)" ;;
esac

check_attestation
out=$(out_dir linux)

cli_build "$triple"
cli=$(cli_path "$triple")
say "smoke: $cli --version"
"$cli" --version
tar_binary "$cli" "$out/$(release_name "linux-$arch-cli.tar.gz")"

if [ "$what" = app ]; then
  frontend
  sidecar "$triple"
  say "app: tauri build --bundles deb,appimage ($PROFILE)"
  # shellcheck disable=SC2086
  (cd app && npx tauri build $TAURI_PROFILE_FLAG --target "$triple" --bundles deb,appimage \
      --config src-tauri/tauri.desktop-cli.conf.json --ci)
  bundle=$CARGO_TARGET_DIR/$triple/$PROFILE/bundle
  deb=$(ls "$bundle"/deb/*.deb | head -n 1)
  image=$(ls "$bundle"/appimage/*.AppImage | head -n 1)
  if [ ! -f "$deb" ] || [ ! -f "$image" ]; then die "tauri produced no .deb or AppImage in $bundle"; fi
  cp "$deb" "$out/$(release_name "linux-$arch.deb")"
  cp "$image" "$out/$(release_name "linux-$arch.AppImage")"
  chmod 0755 "$out/$(release_name "linux-$arch.AppImage")"

  say "smoke: .deb contents and metadata"
  dpkg-deb -f "$deb" Package Version Architecture Depends
  dpkg-deb -c "$deb" | grep -Eq "(^|[ ./])usr/bin/$NAME\$" || die ".deb lacks /usr/bin/$NAME (CLI)"
  dpkg-deb -c "$deb" | grep -Eq "(^|[ ./])usr/bin/$NAME-app\$" || die ".deb lacks the app binary"
  [ "$(dpkg-deb -f "$deb" Version)" = "$APP_VERSION" ] || die ".deb version is not $APP_VERSION"
  [ "$(dpkg-deb -f "$deb" Architecture)" = "$deb_arch" ] || die ".deb architecture is not $deb_arch"
  scratch=$(mktemp -d)
  dpkg-deb -x "$deb" "$scratch"
  desktop=$(ls "$scratch"/usr/share/applications/*.desktop | head -n 1)
  for scheme in $SCHEMES; do
    grep -q "x-scheme-handler/$scheme" "$desktop" || die "the .desktop file does not handle $scheme:// links"
  done
  desktop-file-validate "$desktop" || true
  "$scratch/usr/bin/$NAME" --version

  say "smoke: app --selftest under Xvfb (installed .deb layout)"
  (cd "$scratch" && dbus-run-session -- xvfb-run -a -s "-screen 0 1280x900x24" "./usr/bin/$NAME-app" --selftest)
  say "smoke: AppImage --selftest under Xvfb"
  (cd "$scratch" && APPIMAGE_EXTRACT_AND_RUN=1 dbus-run-session -- xvfb-run -a -s "-screen 0 1280x900x24" "$image" --selftest)
  rm -rf "$scratch"
fi
checksums "$out"
