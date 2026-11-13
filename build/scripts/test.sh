#!/bin/sh
# All app tests (inside build/docker/linux.Dockerfile):
#   1. frontend: TypeScript check + vitest (i18n completeness, links, editor
#      validation, state machines, the page against a mocked invoke layer);
#   2. Rust: the app crate's unit tests (command layer against a mock core) and
#      its integration tests with the real core against the fake website/RPC;
#      clippy on the app crate;
#   3. end-to-end: the desktop app built with the dev-constants feature, driven
#      by tauri-driver + WebKitWebDriver under Xvfb (app/e2e/run.mjs).
#   build/scripts/test.sh [frontend|rust|e2e]...   (default: all three)
. "$(dirname "$0")/common.sh"

parts=${*:-${HELIX_TEST_PARTS:-frontend rust e2e}}
export HELIX_FAKES_PYTHON=/opt/fakes/bin/python
results=${HELIX_OUT:-$RS/dist/test}
mkdir -p "$results"

for part in $parts; do
  case $part in
    frontend)
      frontend
      say "frontend: tsc + vitest"
      (cd app && npx tsc --noEmit && npx vitest run)
      ;;
    rust)
      [ -d app/src-tauri/icons ] || frontend
      say "rust: cargo test -p helix-signer-app (mock core + real core against the fakes)"
      cargo test -p helix-signer-app
      say "rust: clippy -p helix-signer-app"
      cargo clippy -p helix-signer-app --all-targets --no-deps -- -D warnings
      ;;
    e2e)
      [ -d app/node_modules/@tauri-apps/cli ] || frontend
      say "e2e: tauri build --debug --no-bundle --features dev-constants"
      (cd app && npx tauri build --debug --no-bundle --features dev-constants --ci)
      say "e2e: tauri-driver + WebKitWebDriver under Xvfb"
      (cd app && E2E_OUT="$results" dbus-run-session -- xvfb-run -a -s "-screen 0 1280x1000x24" \
        node e2e/run.mjs "$CARGO_TARGET_DIR/debug/awake-helix-signer-app" "$HELIX_FAKES_PYTHON")
      ;;
    *) die "unknown test part $part (frontend, rust, e2e)" ;;
  esac
done
say "tests passed; e2e screenshots in $results"
