# Linux build image: Tauri 2 (webkit2gtk-4.1) .deb + AppImage, the CLI, and
# the end-to-end test tools (Xvfb, WebKitWebDriver, tauri-driver, Python for
# the fake website/RPC). Ubuntu 22.04 keeps the glibc baseline of the
# AppImage low (2.35). Build context: build/docker.
FROM ubuntu:22.04

ARG RUST_TOOLCHAIN
ARG NODE_VERSION
ARG NODE_SHA256_X64
ARG NODE_SHA256_ARM64
ARG RUSTUP_VERSION
ARG RUSTUP_SHA256_X64
ARG RUSTUP_SHA256_ARM64
ARG TAURI_DRIVER_VERSION
ARG UV_VERSION
ARG PYTHON_VERSION
ARG ETH_ACCOUNT_VERSION

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin \
    APPIMAGE_EXTRACT_AND_RUN=1 \
    NO_STRIP=0 \
    LANG=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config curl ca-certificates file git xz-utils \
      libwebkit2gtk-4.1-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev \
      patchelf xvfb xauth dbus-x11 webkit2gtk-driver desktop-file-utils xdg-utils \
      fonts-noto-cjk fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

COPY install-node-rust.sh /usr/local/sbin/
RUN NODE_VERSION=$NODE_VERSION NODE_SHA256_X64=$NODE_SHA256_X64 NODE_SHA256_ARM64=$NODE_SHA256_ARM64 \
    RUSTUP_VERSION=$RUSTUP_VERSION RUSTUP_SHA256_X64=$RUSTUP_SHA256_X64 RUSTUP_SHA256_ARM64=$RUSTUP_SHA256_ARM64 \
    /usr/local/sbin/install-node-rust.sh "$RUST_TOOLCHAIN"

# tauri-driver (WebDriver bridge to WebKitWebDriver) for the end-to-end test.
RUN cargo install --locked --root /usr/local tauri-driver --version "$TAURI_DRIVER_VERSION" \
 && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

# Python with eth-account for the test fakes in tests/py (the fake
# website + RPC that app/e2e/fake_server.py serves).
RUN curl -fsSL "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-$(uname -m)-unknown-linux-gnu.tar.gz" \
      | tar -xz -C /usr/local/bin --strip-components=1 \
 && UV_PYTHON_INSTALL_DIR=/opt/python uv venv --python "$PYTHON_VERSION" /opt/fakes \
 && VIRTUAL_ENV=/opt/fakes uv pip install --no-cache "eth-account==$ETH_ACCOUNT_VERSION" \
 && /opt/fakes/bin/python -c "import eth_account, rlp, eth_abi; print('fakes python ok')"

WORKDIR /src
