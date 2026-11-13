#!/bin/sh
# macOS and iOS builds, run natively on a Mac by build.sh (no container can
# run Xcode). Checks the toolchain first, then:
#   macos  the .app in a .dmg for this Mac's CPU, or universal (arm64 +
#          x86_64) when both Rust targets are installed; ad-hoc signed
#          (codesign -s -) and verified; the CLI as a tarball; smoke tests.
#   ios    `tauri ios build`: an Xcode project and an IPA signed for your own
#          device with your Apple ID's development team (APPLE_DEVELOPMENT_TEAM).
# Usage (via build.sh): HELIX_RELEASE=0|1 build/scripts/apple.sh macos|ios
cd "$(dirname "$0")/../.." || exit 1
. build/scripts/common.sh

platform=$1
[ "$(uname -s)" = Darwin ] || die "$platform builds only on macOS"

say "checking the Apple toolchain"
command -v xcodebuild > /dev/null 2>&1 || die "Xcode is missing: install it from the App Store, then run: sudo xcode-select -s /Applications/Xcode.app && sudo xcodebuild -license accept"
xcodebuild -version | head -n 1
xcode-select -p > /dev/null 2>&1 || die "no developer directory: run xcode-select --install"
command -v rustup > /dev/null 2>&1 || die "rustup is missing: https://rustup.rs (the toolchain $RUST_TOOLCHAIN is read from rust-toolchain.toml)"
rustup toolchain list | grep -q "^$RUST_TOOLCHAIN" || rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
rustc --version | grep -q "$RUST_TOOLCHAIN" || die "rustc is not $RUST_TOOLCHAIN (rust-toolchain.toml)"
command -v node > /dev/null 2>&1 || die "Node.js is missing: install Node $NODE_VERSION (https://nodejs.org or nvm)"
[ "$(node --version)" = "v$NODE_VERSION" ] || say "note: Node $(node --version) is not the pinned v$NODE_VERSION (builds usually still work)"
installed=$(rustup target list --installed)

check_attestation

if [ "$platform" = macos ]; then
  host=$(uname -m)
  case $host in arm64) host_triple=aarch64-apple-darwin; arch=arm64 ;; *) host_triple=x86_64-apple-darwin; arch=x86_64 ;; esac
  if printf '%s\n' "$installed" | grep -q '^aarch64-apple-darwin$' && printf '%s\n' "$installed" | grep -q '^x86_64-apple-darwin$'; then
    targets="aarch64-apple-darwin x86_64-apple-darwin"
    tauri_target=universal-apple-darwin
    arch=universal
  else
    rustup target add "$host_triple" > /dev/null
    targets=$host_triple
    tauri_target=$host_triple
    say "building for $arch only (rustup target add aarch64-apple-darwin x86_64-apple-darwin for a universal build)"
  fi
  out=$(out_dir macos)
  for target in $targets; do cli_build "$target"; done
  mkdir -p app/src-tauri/binaries
  if [ "$arch" = universal ]; then
    lipo -create -output app/src-tauri/binaries/awake-helix-signer-universal-apple-darwin \
      "$(cli_path aarch64-apple-darwin)" "$(cli_path x86_64-apple-darwin)"
    # Tauri also looks up per-architecture sidecars while compiling each slice.
    sidecar aarch64-apple-darwin
    sidecar x86_64-apple-darwin
    cli=app/src-tauri/binaries/awake-helix-signer-universal-apple-darwin
  else
    sidecar "$host_triple"
    cli=$(cli_path "$host_triple")
  fi
  say "smoke: CLI --version"
  "$cli" --version
  tar_binary "$cli" "$out/$(release_name "macos-$arch-cli.tar.gz")"
  frontend
  say "app: tauri build --bundles app,dmg --target $tauri_target ($PROFILE)"
  # CI=true makes Tauri skip the Finder AppleScript that lays out the .dmg
  # window: it times out without a logged-in desktop (e.g. over SSH).
  # shellcheck disable=SC2086
  (cd app && CI=true npx tauri build $TAURI_PROFILE_FLAG --target "$tauri_target" --bundles app,dmg \
      --config src-tauri/tauri.desktop-cli.conf.json --ci)
  bundle=$CARGO_TARGET_DIR/$tauri_target/$PROFILE/bundle
  app_dir=$(ls -d "$bundle"/macos/*.app | head -n 1)
  dmg=$(ls "$bundle"/dmg/*.dmg | head -n 1)
  if [ ! -d "$app_dir" ] || [ ! -f "$dmg" ]; then die "tauri produced no .app or .dmg in $bundle"; fi
  say "verify: ad-hoc signature, URL scheme, bundled CLI"
  codesign --verify --deep --strict --verbose=2 "$app_dir"
  codesign -dv "$app_dir" 2>&1 | grep -E 'Signature=adhoc|Identifier=' || true
  /usr/libexec/PlistBuddy -c 'Print :CFBundleURLTypes:0:CFBundleURLSchemes:0' "$app_dir/Contents/Info.plist" | grep -qx awakehelix ||
    die "Info.plist does not register awakehelix://"
  [ -x "$app_dir/Contents/MacOS/awake-helix-signer" ] || die "the .app does not contain the CLI"
  "$app_dir/Contents/MacOS/awake-helix-signer" --version
  say "smoke: app --selftest (opens a window for a few seconds)"
  "$app_dir/Contents/MacOS/awake-helix-signer-app" --selftest
  cp "$dmg" "$out/$(release_name "macos-$arch.dmg")"
  checksums "$out"
  exit 0
fi

# ---------------------------------------------------------------------- iOS
[ "$platform" = ios ] || die "unknown platform $platform"
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  printf '%s\n' "$installed" | grep -q "^$target\$" || rustup target add "$target"
done
command -v xcodegen > /dev/null 2>&1 || die "XcodeGen is missing (Tauri generates the Xcode project with it): brew install xcodegen"
command -v pod > /dev/null 2>&1 || die "CocoaPods is missing (tauri ios init runs pod install): brew install cocoapods"
# With APPLE_DEVELOPMENT_TEAM: an IPA signed for your registered devices (needs the
# login keychain unlocked, i.e. run it in Terminal on the Mac, not over SSH).
# Without it: an unsigned IPA for SideStore/AltStore, which sign it with your
# Apple ID when installing (no Apple account in Xcode needed).
if [ -n "${APPLE_DEVELOPMENT_TEAM:-}" ]; then
  signing=signed
  ipa_name=ios.ipa
else
  signing=unsigned
  ipa_name=ios-unsigned.ipa
  say "APPLE_DEVELOPMENT_TEAM is not set: building an unsigned IPA for SideStore/AltStore (they sign it when installing)"
fi
out=$(out_dir ios)
frontend
cd app || exit 1
# A failed earlier init can leave gen/apple without its Xcode project: start over.
if ! ls -d src-tauri/gen/apple/*.xcodeproj > /dev/null 2>&1; then
  rm -rf src-tauri/gen/apple
  say "tauri ios init"
  npx tauri ios init --ci
fi
if [ "$signing" = signed ]; then
  say "app: tauri ios build --export-method debugging ($PROFILE)"
  # shellcheck disable=SC2086
  npx tauri ios build $TAURI_PROFILE_FLAG --export-method debugging --ci
else
  say "app: tauri ios build --no-sign ($PROFILE)"
  # shellcheck disable=SC2086
  npx tauri ios build $TAURI_PROFILE_FLAG --no-sign --ci
fi
cd .. || exit 1
ipa=$(find app/src-tauri/gen/apple/build -name '*.ipa' | head -n 1)
if [ -z "$ipa" ] && [ "$signing" = unsigned ]; then
  # An unsigned build stops at the archive: package its .app as Payload/ in a zip (an IPA).
  app_bundle=$(find app/src-tauri/gen/apple/build -type d -name '*.app' -path '*.xcarchive/Products/Applications/*' | head -n 1)
  [ -n "$app_bundle" ] || die "no .app in an .xcarchive under app/src-tauri/gen/apple/build"
  staging=$(mktemp -d)
  mkdir "$staging/Payload"
  ditto "$app_bundle" "$staging/Payload/$(basename "$app_bundle")"
  ipa=$staging/app.ipa
  (cd "$staging" && zip -qry app.ipa Payload)
fi
[ -n "$ipa" ] || die "no IPA produced (open app/src-tauri/gen/apple/*.xcodeproj in Xcode to see the signing error)"
say "verify: IPA contents and URL scheme"
listing=$(unzip -l "$ipa")
printf '%s\n' "$listing" | grep -q 'Payload/.*\.app/Info.plist' || die "the IPA has no Payload/*.app/Info.plist"
check=$(mktemp -d)
unzip -q "$ipa" 'Payload/*.app/Info.plist' -d "$check"
info=$(find "$check/Payload" -maxdepth 2 -name Info.plist | head -n 1)
/usr/libexec/PlistBuddy -c 'Print :CFBundleURLTypes:0:CFBundleURLSchemes:0' "$info" | grep -qx awakehelix || die "Info.plist does not register awakehelix://"
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$info"
/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$info"
/usr/libexec/PlistBuddy -c 'Print :MinimumOSVersion' "$info"
cp "$ipa" "$out/$(release_name "$ipa_name")"
if [ "$signing" = signed ]; then
  say "Xcode project: app/src-tauri/gen/apple ; install the IPA with Xcode (Window > Devices and Simulators) or Apple Configurator"
else
  say "install $(release_name "$ipa_name") with SideStore or AltStore on the iPhone (they sign it with your Apple ID)"
fi
checksums "$out"
