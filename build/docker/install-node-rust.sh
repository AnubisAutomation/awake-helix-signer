#!/bin/sh
# Install the pinned Node.js and Rust toolchain into a build image (both
# downloads are checked against pinned SHA-256 sums). Used by every Dockerfile.
#   install-node-rust.sh <rust-toolchain> [extra rustup targets...]
set -eu
toolchain=$1
shift
case "$(uname -m)" in
  x86_64) node_arch=x64; node_sum=$NODE_SHA256_X64; rust_arch=x86_64; rust_sum=$RUSTUP_SHA256_X64 ;;
  aarch64) node_arch=arm64; node_sum=$NODE_SHA256_ARM64; rust_arch=aarch64; rust_sum=$RUSTUP_SHA256_ARM64 ;;
  *) echo "unsupported build CPU $(uname -m)" >&2; exit 1 ;;
esac
tmp=$(mktemp -d)
curl -fsSL -o "$tmp/node.tar.xz" "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$node_arch.tar.xz"
echo "$node_sum  $tmp/node.tar.xz" | sha256sum -c -
tar -xJf "$tmp/node.tar.xz" -C /usr/local --strip-components=1 --exclude='*/share/doc' --exclude='*/include'
curl -fsSL -o "$tmp/rustup-init" "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/$rust_arch-unknown-linux-gnu/rustup-init"
echo "$rust_sum  $tmp/rustup-init" | sha256sum -c -
chmod +x "$tmp/rustup-init"
"$tmp/rustup-init" -y --no-modify-path --profile minimal --default-toolchain "$toolchain" -c rustfmt,clippy
for target in "$@"; do rustup target add --toolchain "$toolchain" "$target"; done
rm -rf "$tmp" "$CARGO_HOME/registry" "$RUSTUP_HOME/downloads" "$RUSTUP_HOME/tmp"
node --version
rustc --version
