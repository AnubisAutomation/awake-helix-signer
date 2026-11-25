# shellcheck shell=sh
# Helpers sourced by the per-platform build scripts. They run inside the
# build containers (and natively on macOS) with the repository root as the
# working directory. POSIX sh.
#
# Environment set by build.sh:
#   HELIX_RELEASE   1 for an optimized, --locked release build, 0 for a debug build
#   HELIX_OUT       artifact directory (default dist/<platform>)
#   CARGO_TARGET_DIR  cargo target directory (a named volume in containers)

set -eu

say() { printf '==> %s\n' "$*" >&2; }
die() { printf 'build: %s\n' "$*" >&2; exit 1; }

RS=$(pwd)
# shellcheck disable=SC2034 # used by the scripts that source this file
{
  # The command, the release file names and the app identifier (tauri.conf.json).
  NAME=anubisauto-signer
  IDENTIFIER=com.sivilization.anubisauto.signer
  # Every link scheme the app registers: anubisauto, and awakehelix so the
  # links of the signers before 0.7.0 still open it.
  SCHEMES="anubisauto awakehelix"
}
APP_VERSION=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$RS/Cargo.toml" | head -n 1)
HELIX_RELEASE=${HELIX_RELEASE:-0}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$RS/target}
export CARGO_TARGET_DIR
[ -n "$APP_VERSION" ] || die "cannot read the workspace version from Cargo.toml"

# shellcheck disable=SC2034 # used by the scripts that source this file
if [ "$HELIX_RELEASE" = 1 ]; then
  PROFILE=release
  CARGO_PROFILE_FLAG=--release
  CARGO_LOCKED=--locked
  TAURI_PROFILE_FLAG=
else
  PROFILE=debug
  CARGO_PROFILE_FLAG=
  CARGO_LOCKED=
  TAURI_PROFILE_FLAG=--debug
fi

# The attestation address pinned into the build must be the release one: the
# placeholder (whose private key nobody knows) would make every grant fail.
check_attestation() {
  file=$RS/attestation_address.txt
  constants=$RS/crates/helix-signer-core/src/constants.rs
  [ -f "$file" ] || die "$file is missing"
  address=$(tr -d ' \t\r\n' < "$file")
  placeholder=$(sed -n 's/^pub const ATTESTATION_PLACEHOLDER: &str = "\(0x[0-9a-fA-F]*\)";.*/\1/p' "$constants")
  [ -n "$placeholder" ] || die "ATTESTATION_PLACEHOLDER not found in $constants"
  printf '%s\n' "$address" | grep -Eq '^0x[0-9a-fA-F]{40}$' || die "$file must hold one 0x address, found '$address'"
  lower=$(printf '%s' "$address" | tr 'A-F' 'a-f')
  [ "$lower" != "0x0000000000000000000000000000000000000000" ] || die "$file holds the zero address"
  if [ "$lower" = "$(printf '%s' "$placeholder" | tr 'A-F' 'a-f')" ]; then
    die "$file still holds the build placeholder $placeholder: set it to the platform attestation address published by the Anubis Automation website before building a release."
  fi
  say "attestation address $address (release value, not the placeholder)"
}

# Pinned Node/npm and the frontend dependencies (package-lock.json).
frontend() {
  say "frontend: npm ci, icons, vite build"
  node_major=$(node --version | sed 's/^v\([0-9]*\).*/\1/')
  [ "$node_major" -ge 22 ] || die "Node $(node --version) is too old (need 22 or newer)"
  (cd "$RS/app" && npm ci --no-audit --no-fund --loglevel=error && npm run --silent icons > /dev/null)
}

# Build the CLI for one Rust target with an optional cargo runner prefix ("xwin").
cli_build() {
  target=$1
  runner=${2:-}
  say "CLI: cargo ${runner:+$runner }build -p helix-signer-cli --target $target ($PROFILE)"
  if [ -n "$runner" ]; then
    # shellcheck disable=SC2086
    cargo "$runner" build -p helix-signer-cli --target "$target" $CARGO_PROFILE_FLAG $CARGO_LOCKED
  else
    # shellcheck disable=SC2086
    cargo build -p helix-signer-cli --target "$target" $CARGO_PROFILE_FLAG $CARGO_LOCKED
  fi
}

# The CLI binary of a target, and the Tauri sidecar copy next to the app sources.
cli_path() {
  case $1 in
    *windows*) printf '%s/%s/%s/%s.exe' "$CARGO_TARGET_DIR" "$1" "$PROFILE" "$NAME" ;;
    *) printf '%s/%s/%s/%s' "$CARGO_TARGET_DIR" "$1" "$PROFILE" "$NAME" ;;
  esac
}

sidecar() {
  target=$1
  src=$(cli_path "$target")
  [ -f "$src" ] || die "CLI binary $src is missing"
  mkdir -p "$RS/app/src-tauri/binaries"
  case $target in
    *windows*) cp "$src" "$RS/app/src-tauri/binaries/$NAME-$target.exe" ;;
    *) cp "$src" "$RS/app/src-tauri/binaries/$NAME-$target" ;;
  esac
}

out_dir() {
  dir=${HELIX_OUT:-$RS/dist/$1}
  mkdir -p "$dir"
  printf '%s' "$dir"
}

# A release file name: anubisauto-signer-<version>-<suffix>, "-debug" for a debug build.
release_name() {
  if [ "$HELIX_RELEASE" = 1 ]; then
    printf '%s-%s-%s' "$NAME" "$APP_VERSION" "$1"
  else
    printf '%s-%s-debug-%s' "$NAME" "$APP_VERSION" "$1"
  fi
}

# sha256sum on Linux, shasum on macOS (same output format).
sha256() {
  if command -v sha256sum > /dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# Write <file>.sha256 for each file and a SHA256SUMS over the directory.
checksums() {
  dir=$1
  (
    cd "$dir"
    rm -f SHA256SUMS ./*.sha256
    for file in *; do
      [ -f "$file" ] || continue
      sha256 "$file" > "$file.sha256"
    done
    cat ./*.sha256 > SHA256SUMS 2>/dev/null || true
    sha256 -c SHA256SUMS > /dev/null
  )
  say "artifacts in $dir:"
  (cd "$dir" && for file in *; do case $file in *.sha256|SHA256SUMS) ;; *) [ -f "$file" ] && printf '    %10s  %s  %s\n' "$(wc -c < "$file" | tr -d ' ')" "$(cut -c1-16 "$file.sha256")" "$file" >&2 ;; esac; done)
}

# Tar one binary as <name>.tar.gz containing just that binary (mode 0755).
tar_binary() {
  binary=$1
  archive=$2
  staging=$(mktemp -d)
  cp "$binary" "$staging/$NAME"
  chmod 0755 "$staging/$NAME"
  if tar --version 2> /dev/null | grep -q GNU; then
    tar -C "$staging" --owner=0 --group=0 --numeric-owner -czf "$archive" "$NAME"
  else
    tar -C "$staging" --uid 0 --gid 0 -czf "$archive" "$NAME"
  fi
  rm -rf "$staging"
}
