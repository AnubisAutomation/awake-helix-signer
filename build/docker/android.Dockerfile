# Android build image: JDK 17, the Android SDK command-line tools, the
# pinned NDK, the platforms and build-tools the Tauri template compiles
# against, Node and Rust with the arm64-v8a and x86_64 Android targets. The
# emulator and its system image are NOT in the image: build.sh installs them
# into a named volume only when /dev/kvm is usable. Each ARG is declared just
# before the layer that uses it, so changing one pin rebuilds only that layer
# and the ones after it. Build context: build/docker.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    GRADLE_USER_HOME=/cache/gradle \
    LANG=C.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config curl ca-certificates file git xz-utils unzip \
      openjdk-17-jdk-headless \
      libpulse0 libgl1 libnss3 libxcomposite1 libxcursor1 libxi6 libxtst6 libxrandr2 libasound2t64 libxkbfile1 libdbus-1-3 \
 && rm -rf /var/lib/apt/lists/*

ARG ANDROID_CMDLINE_TOOLS
ARG ANDROID_CMDLINE_TOOLS_SHA1
ARG ANDROID_NDK_VERSION
RUN curl -fsSL -o /tmp/tools.zip "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS}_latest.zip" \
 && echo "${ANDROID_CMDLINE_TOOLS_SHA1}  /tmp/tools.zip" | sha1sum -c - \
 && mkdir -p /opt/android-sdk/cmdline-tools \
 && unzip -q /tmp/tools.zip -d /opt/android-sdk/cmdline-tools \
 && mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest \
 && rm /tmp/tools.zip \
 && export PATH="/opt/android-sdk/cmdline-tools/latest/bin:$PATH" \
 && yes | sdkmanager --licenses > /dev/null \
 && sdkmanager --install "platform-tools" "ndk;${ANDROID_NDK_VERSION}" > /dev/null \
 && rm -rf /root/.android/cache /opt/android-sdk/.temp \
 && ls /opt/android-sdk/ndk

# The template compiles against android-37.0; some Tauri plugin libraries against android-36.
ARG ANDROID_PLATFORMS
ARG ANDROID_BUILD_TOOLS
RUN export PATH="/opt/android-sdk/cmdline-tools/latest/bin:$PATH" \
 && sdkmanager --install $(for p in ${ANDROID_PLATFORMS}; do printf 'platforms;%s ' "$p"; done) "build-tools;${ANDROID_BUILD_TOOLS}" > /dev/null \
 && rm -rf /root/.android/cache /opt/android-sdk/.temp \
 && ls /opt/android-sdk/platforms /opt/android-sdk/build-tools

ARG RUST_TOOLCHAIN
ARG NODE_VERSION
ARG NODE_SHA256_X64
ARG NODE_SHA256_ARM64
ARG RUSTUP_VERSION
ARG RUSTUP_SHA256_X64
ARG RUSTUP_SHA256_ARM64
COPY install-node-rust.sh /usr/local/sbin/
RUN NODE_VERSION=$NODE_VERSION NODE_SHA256_X64=$NODE_SHA256_X64 NODE_SHA256_ARM64=$NODE_SHA256_ARM64 \
    RUSTUP_VERSION=$RUSTUP_VERSION RUSTUP_SHA256_X64=$RUSTUP_SHA256_X64 RUSTUP_SHA256_ARM64=$RUSTUP_SHA256_ARM64 \
    PATH=/usr/local/cargo/bin:$PATH \
    /usr/local/sbin/install-node-rust.sh "$RUST_TOOLCHAIN" aarch64-linux-android x86_64-linux-android

ENV NDK_HOME=/opt/android-sdk/ndk/${ANDROID_NDK_VERSION} \
    ANDROID_BUILD_TOOLS=${ANDROID_BUILD_TOOLS} \
    PATH=/usr/local/cargo/bin:/usr/local/bin:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/build-tools/${ANDROID_BUILD_TOOLS}:/usr/bin:/bin

WORKDIR /src
