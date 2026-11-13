# Windows build image: cross-compiles the Tauri app and the CLI for
# x86_64-pc-windows-msvc from Linux with cargo-xwin (clang-cl + lld-link and
# the MSVC CRT/Windows SDK that cargo-xwin downloads into its cache volume)
# and packs the NSIS installer with makensis, as Tauri 2 supports. The app
# uses the WebView2 download bootstrapper (installed on first run if missing).
# Wine runs the CLI .exe as a smoke test. Build context: build/docker.
FROM ubuntu:24.04

ARG RUST_TOOLCHAIN
ARG NODE_VERSION
ARG NODE_SHA256_X64
ARG NODE_SHA256_ARM64
ARG RUSTUP_VERSION
ARG RUSTUP_SHA256_X64
ARG RUSTUP_SHA256_ARM64
ARG CARGO_XWIN_VERSION

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/lib/llvm-18/bin:/usr/bin:/bin \
    XWIN_ACCEPT_LICENSE=1 \
    WINEDEBUG=-all \
    LANG=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config curl ca-certificates file git xz-utils \
      nsis lld llvm clang \
      wine wine64 \
 && rm -rf /var/lib/apt/lists/*

COPY install-node-rust.sh /usr/local/sbin/
RUN NODE_VERSION=$NODE_VERSION NODE_SHA256_X64=$NODE_SHA256_X64 NODE_SHA256_ARM64=$NODE_SHA256_ARM64 \
    RUSTUP_VERSION=$RUSTUP_VERSION RUSTUP_SHA256_X64=$RUSTUP_SHA256_X64 RUSTUP_SHA256_ARM64=$RUSTUP_SHA256_ARM64 \
    /usr/local/sbin/install-node-rust.sh "$RUST_TOOLCHAIN" x86_64-pc-windows-msvc

RUN cargo install --locked --root /usr/local cargo-xwin --version "$CARGO_XWIN_VERSION" \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git" \
 && makensis -VERSION && command -v llvm-rc lld-link clang-cl && (command -v wine || ls /usr/lib/wine/wine64)

WORKDIR /src
