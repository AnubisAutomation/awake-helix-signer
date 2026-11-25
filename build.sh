#!/bin/sh
# Build the Anubis Automation Script Signer (Tauri app + CLI) for one platform. Linux,
# Windows and Android build in a container (Docker); macOS and iOS build
# natively on a Mac with Xcode (Apple's toolchains do not run in containers).
#
#   ./build.sh <platform> [--out DIR] [--release] [--keep-cache] [--arch x86_64|arm64] [--emulator|--no-emulator]
#
#   linux           .deb + AppImage + CLI tarball (container, Ubuntu 22.04)
#   windows         NSIS setup .exe + CLI .exe (container, cross-compiled with cargo-xwin)
#   android         signed universal APK, arm64-v8a + x86_64 (container, JDK 17 + SDK + NDK)
#   macos           .app in a .dmg (+ CLI), ad-hoc signed; universal when both Rust targets exist (Mac only)
#   ios             IPA (Mac only): unsigned for SideStore/AltStore, or signed for your devices with APPLE_DEVELOPMENT_TEAM
#   cli-linux       only the Linux CLI tarball (container)
#   cli-windows     only the Windows CLI .exe (container)
#   all             every platform this computer can build: linux, windows and android in
#                   containers, plus macos (and ios when APPLE_DEVELOPMENT_TEAM is set) on a Mac
#   all-linux-host  linux, windows and android one after the other (container)
#   test            app unit tests, frontend tests and the desktop end-to-end test (container)
#   images          only build the container images (linux, windows, android)
#   clean           remove everything the build left behind (see --keep-cache)
#
#   --out DIR       artifact directory (default dist/<platform>)
#   --release       optimized build with Cargo.lock enforced (--locked); without it a debug
#                   build is made and every file name carries "-debug"
#   --keep-cache    keep the build caches for a faster next build. By default every
#                   build ends (also when it fails) by removing what it created: this
#                   script's Docker images, volumes (cargo, npm, Gradle, SDK, emulator),
#                   its BuildKit builder and build cache, and the generated files in
#                   app/ (dist, src-tauri/gen, binaries, icons); on a Mac also
#                   the cargo/npm caches and Xcode DerivedData of the build. Kept:
#                   dist/ (the results) and the Android signing key.
#   --arch arm64    linux only: build for arm64 under QEMU (needs docker buildx + binfmt)
#   --emulator      android: also boot an emulator and install the APK (needs /dev/kvm;
#                   default: on when /dev/kvm is usable); --no-emulator skips it
#
# Environment:
#   HELIX_ANDROID_KEYSTORE                release keystore (default ~/.awake-helix-signing/android-release.jks,
#                                         generated on first use; BACK IT UP)
#   HELIX_ANDROID_KEYSTORE_PASSWORD_FILE  its password file (default: next to it, .password, mode 0600)
#   HELIX_ANDROID_KEY_ALIAS               key alias (default: the keystore's only key; anubisauto-signer
#                                         for a new keystore)
#   HELIX_MIN_FREE_GB                     refuse to start below this much free disk (default 10)
#   HELIX_WAIT_MAX                        seconds to wait for a busy machine (default 1800)
#   HELIX_TEST_PARTS                      test: a subset of "frontend rust e2e"
#   HELIX_KEEP_CACHE=1                    same as --keep-cache
#   APPLE_DEVELOPMENT_TEAM                ios: team ID for a signed IPA (Xcode > Settings > Accounts); unset: unsigned IPA
set -eu

RS=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$RS/build/versions.env"
RUST_TOOLCHAIN=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$RS/rust-toolchain.toml")
MIN_FREE_GB=${HELIX_MIN_FREE_GB:-10}
WAIT_MAX=${HELIX_WAIT_MAX:-1800}
PREFIX=anubisauto-signer

say() { printf '==> %s\n' "$*" >&2; }
die() { printf 'build.sh: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

[ $# -ge 1 ] || usage
platform=$1
shift
out=""
release=0
arch=x86_64
emulator=auto
keep_cache=${HELIX_KEEP_CACHE:-0}
while [ $# -gt 0 ]; do
  case $1 in
    --out) [ $# -ge 2 ] || usage; out=$2; shift 2 ;;
    --out=*) out=${1#--out=}; shift ;;
    --release) release=1; shift ;;
    --keep-cache) keep_cache=1; shift ;;
    --arch) [ $# -ge 2 ] || usage; arch=$2; shift 2 ;;
    --arch=*) arch=${1#--arch=}; shift ;;
    --emulator) emulator=1; shift ;;
    --no-emulator) emulator=0; shift ;;
    -h|--help) usage ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done
case $arch in x86_64|arm64) ;; *) die "--arch must be x86_64 or arm64" ;; esac
if [ -n "$out" ]; then
  mkdir -p "$out"
  out=$(CDPATH='' cd -- "$out" && pwd)
fi

# ------------------------------------------------------------------ checks

free_gb() {
  df -Pk "$1" 2> /dev/null | awk 'NR == 2 { print int($4 / 1048576) }'
}

# Stop before a step that needs about $1 GB when less than that plus the reserve is free.
need_disk() {
  for place in / "$(docker info -f '{{.DockerRootDir}}' 2> /dev/null || echo /)"; do
    free=$(free_gb "$place")
    [ -n "$free" ] || continue
    if [ "$free" -lt $(($1 + MIN_FREE_GB)) ]; then
      die "only $free GB free on $place; this step needs about $1 GB and $MIN_FREE_GB GB must stay free. Free space (build.sh clean removes this script's caches) or set HELIX_MIN_FREE_GB."
    fi
  done
  say "disk: $(free_gb /) GB free on / (step needs ~$1 GB, reserve $MIN_FREE_GB GB)"
}

# GB a build step needs: $1 for a first build, $2 when its cache volume $3 already exists.
estimate() {
  if docker volume inspect "$3" > /dev/null 2>&1; then printf '%s' "$2"; else printf '%s' "$1"; fi
}

# One heavy build at a time; also wait while the machine is loaded.
LOCK=${TMPDIR:-/tmp}/$PREFIX-build.lock
have_lock=0
do_cleanup=0
take_lock() {
  [ "$have_lock" = 0 ] || return 0
  waited=0
  while ! mkdir "$LOCK" 2> /dev/null; do
    [ "$waited" -lt "$WAIT_MAX" ] || die "another build.sh holds $LOCK (remove it if no build runs)"
    [ "$waited" = 0 ] && say "waiting for the other signer build to finish ($LOCK)"
    sleep 15
    waited=$((waited + 15))
  done
  have_lock=1
  cpus=$(getconf _NPROCESSORS_ONLN 2> /dev/null || echo 4)
  waited=0
  while [ -r /proc/loadavg ]; do
    load=$(cut -d' ' -f1 /proc/loadavg | cut -d. -f1)
    [ "$load" -lt "$cpus" ] && break
    [ "$waited" -lt "$WAIT_MAX" ] || { say "machine still busy (load $load on $cpus CPUs); starting anyway"; break; }
    [ "$waited" = 0 ] && say "machine busy (load $load on $cpus CPUs); waiting"
    sleep 30
    waited=$((waited + 30))
  done
}

need_docker() {
  command -v docker > /dev/null 2>&1 || die "Docker is required for $platform (Docker Engine on Linux, Docker Desktop on Windows/macOS)"
  docker info > /dev/null 2>&1 || die "Docker is installed but not running (start Docker Desktop / the docker service)"
}

# ------------------------------------------------------------------ images

# Images are built by a BuildKit builder of their own, so the build cache they
# leave can be removed with the builder without touching anyone else's cache.
BUILDER=$PREFIX
ensure_builder() {
  docker buildx inspect "$BUILDER" > /dev/null 2>&1 && return 0
  docker buildx version > /dev/null 2>&1 ||
    die "Docker Buildx is required (part of Docker Desktop; on Linux install the docker-buildx-plugin package)"
  say "creating the BuildKit builder $BUILDER ($BUILDKIT_IMAGE)"
  docker buildx create --name "$BUILDER" --driver docker-container \
    --driver-opt "image=$BUILDKIT_IMAGE" > /dev/null
}

files_hash() {
  cat "$@" | { sha256sum 2> /dev/null || shasum -a 256; } | cut -c1-12
}

# Build (once) the image for a platform; old images of the same platform are removed.
image_for() {
  kind=$1
  docker_platform=$2
  dockerfile=$RS/build/docker/$kind.Dockerfile
  hash=$(printf '%s %s' "$RUST_TOOLCHAIN" "$docker_platform" | cat - "$dockerfile" "$RS/build/docker/install-node-rust.sh" "$RS/build/versions.env" | { sha256sum 2> /dev/null || shasum -a 256; } | cut -c1-12)
  suffix=""
  [ "$docker_platform" = linux/amd64 ] || suffix=-$(printf '%s' "$docker_platform" | tr '/' '-')
  image=$PREFIX-build-$kind$suffix:$hash
  if ! docker image inspect "$image" > /dev/null 2>&1; then
    # An older image of this kind means most layers come from the build cache.
    if [ -n "$(docker images -q "$PREFIX-build-$kind$suffix" 2> /dev/null)" ]; then
      need_disk 2
    else
      case $kind in android) need_disk 8 ;; *) need_disk 4 ;; esac
    fi
    say "building image $image (once; cached afterwards)"
    # One --build-arg per NAME=value line of versions.env (values may hold spaces).
    set -- --build-arg RUST_TOOLCHAIN="$RUST_TOOLCHAIN"
    while IFS= read -r line; do
      case $line in BUILDKIT_IMAGE=*) continue ;; [A-Z]*=*) ;; *) continue ;; esac
      value=${line#*=}
      value=${value#\'}
      set -- "$@" --build-arg "${line%%=*}=${value%\'}"
    done < "$RS/build/versions.env"
    ensure_builder
    docker buildx build --builder "$BUILDER" --load --platform "$docker_platform" -t "$image" -f "$dockerfile" "$@" "$RS/build/docker" >&2
    docker images --format '{{.Repository}}:{{.Tag}}' "$PREFIX-build-$kind$suffix" | grep -v ":$hash\$" | xargs -r docker rmi > /dev/null 2>&1 || true
  fi
  printf '%s' "$image"
}

# Run a build script in a container with this repository (mounted at /src; it
# never reads its parent directory, so it works as a standalone clone and as a
# subdirectory of another checkout) and the caches mounted:
#   run_in <kind> <docker platform> [docker run options...] -- <script> [args...]
run_in() {
  kind=$1
  docker_platform=$2
  shift 2
  image=$(image_for "$kind" "$docker_platform") || exit 1
  cache=$kind$( [ "$docker_platform" = linux/amd64 ] || printf -- '-%s' "${docker_platform#linux/}")
  # Replace "--" with "-w /src <image> sh" (rotating the arguments keeps their quoting).
  n=$#
  while [ "$n" -gt 0 ]; do
    arg=$1
    shift
    if [ "$arg" = -- ]; then set -- "$@" -w /src "$image" sh; else set -- "$@" "$arg"; fi
    n=$((n - 1))
  done
  docker run --rm --init --platform "$docker_platform" \
    --label "$PREFIX.build=$kind" \
    -v "$RS:/src" \
    -v "$PREFIX-cargo-registry:/usr/local/cargo/registry" \
    -v "$PREFIX-cargo-git:/usr/local/cargo/git" \
    -v "$PREFIX-target-$cache:/cache/target" \
    -v "$PREFIX-node-modules-$cache:/src/app/node_modules" \
    -v "$PREFIX-npm:/cache/npm" \
    -v "$PREFIX-tools-$cache:/root/.cache" \
    -e CARGO_TARGET_DIR=/cache/target \
    -e npm_config_cache=/cache/npm \
    -e HELIX_RELEASE="$release" \
    -e CI=true \
    ${out:+-v "$out:/out"} ${out:+-e HELIX_OUT=/out} \
    "$@"
}

# ----------------------------------------------------------------- cleanup

# Remove generated files under app/. On a Linux host the containers
# wrote them as root, so files this user cannot delete go through a container.
clean_repo_files() {
  app=$RS/app
  set -- "$app/dist" "$app/src-tauri/gen" "$app/src-tauri/binaries" "$app/src-tauri/icons" "$app/src-tauri/app-icon.png"
  [ "$1" != /dist ] || return 0
  rm -rf "$@" 2> /dev/null || true
  left=""
  for path in "$@"; do [ ! -e "$path" ] || left=1; done
  if [ -n "$left" ] && docker info > /dev/null 2>&1; then
    helper=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep "^$PREFIX-build-" | head -n 1)
    [ -z "$helper" ] || docker run --rm --entrypoint rm -v "$app:/app" "$helper" -rf \
      /app/dist /app/src-tauri/gen /app/src-tauri/binaries /app/src-tauri/icons /app/src-tauri/app-icon.png > /dev/null 2>&1 || true
  fi
  # The node_modules volume's mount point (an empty directory) after container builds.
  rmdir "$app/node_modules" 2> /dev/null || true
  for path in "$@"; do [ ! -e "$path" ] || say "could not remove $path (remove it by hand)"; done
}

# Native Mac builds keep their caches under .build-cache/; Xcode adds DerivedData.
clean_native_files() {
  [ -n "${NATIVE_CACHE:-}" ] || return 0
  case $NATIVE_CACHE in "$RS"/.build-cache) rm -rf "$NATIVE_CACHE" ;; esac
  rm -rf "$RS/app/node_modules"
  for derived in "$HOME"/Library/Developer/Xcode/DerivedData/*; do
    [ -f "$derived/info.plist" ] || continue
    workspace=$(plutil -extract WorkspacePath raw "$derived/info.plist" 2> /dev/null || true)
    case $workspace in "$RS"/app/*) rm -rf "$derived" ;; esac
  done
}

clean_docker() {
  docker info > /dev/null 2>&1 || return 0
  docker ps -aq --filter "label=$PREFIX.build" | xargs -r docker rm -f > /dev/null 2>&1 || true
  # Generated files first: removing root-owned ones may need one of the images.
  clean_repo_files
  docker images --format '{{.Repository}}:{{.Tag}}' | grep "^$PREFIX-build-" | xargs -r docker rmi -f > /dev/null 2>&1 || true
  docker volume ls -q --filter "name=^$PREFIX-" | xargs -r docker volume rm -f > /dev/null 2>&1 || true
  # Removing the builder also removes its build cache (its state volume).
  docker buildx rm --force "$BUILDER" > /dev/null 2>&1 || docker buildx rm "$BUILDER" > /dev/null 2>&1 || true
  # Also when buildx lost track of it: the builder's container and state volume by name.
  docker rm -f "buildx_buildkit_${BUILDER}0" > /dev/null 2>&1 || true
  docker volume rm -f "buildx_buildkit_${BUILDER}0_state" > /dev/null 2>&1 || true
  if [ -z "$(docker ps -aq --filter "ancestor=$BUILDKIT_IMAGE")" ]; then
    docker rmi "$BUILDKIT_IMAGE" > /dev/null 2>&1 || true
  fi
}

cleanup() {
  if [ "$keep_cache" = 1 ]; then
    say "kept the build caches (--keep-cache); build.sh clean removes them"
    return 0
  fi
  before=$(free_gb /)
  say "cleaning up what the build created (kept: dist/ and the Android signing key; --keep-cache skips this)"
  clean_docker
  clean_repo_files
  clean_native_files
  say "cleanup done: $(free_gb /) GB free on / (was $before GB)"
}

on_exit() {
  status=$?
  trap - EXIT
  set +e
  [ "$do_cleanup" = 0 ] || cleanup
  [ "$have_lock" = 0 ] || rmdir "$LOCK" 2> /dev/null
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ----------------------------------------------------------------- targets

container_linux() {
  what=$1
  docker_platform=linux/amd64
  if [ "$arch" = arm64 ]; then
    docker_platform=linux/arm64
    docker buildx version > /dev/null 2>&1 || die "--arch arm64 needs docker buildx"
    docker run --rm --platform linux/arm64 ubuntu:22.04 true > /dev/null 2>&1 ||
      die "this Docker cannot run linux/arm64 containers: install QEMU binfmt (docker run --privileged --rm tonistiigi/binfmt --install arm64)"
    say "linux/arm64 runs under QEMU emulation: expect a slow build"
  fi
  need_disk "$(estimate 6 2 "$PREFIX-target-linux")"
  run_in linux "$docker_platform" -- build/scripts/linux.sh "$what"
}

container_windows() {
  need_disk "$(estimate 6 2 "$PREFIX-target-windows")"
  run_in windows linux/amd64 -- build/scripts/windows.sh "$1"
}

container_android() {
  keystore=${HELIX_ANDROID_KEYSTORE:-$HOME/.awake-helix-signing/android-release.jks}
  password_file=${HELIX_ANDROID_KEYSTORE_PASSWORD_FILE:-${keystore%.*}.password}
  alias=${HELIX_ANDROID_KEY_ALIAS:-}
  signing_dir=$(dirname "$keystore")
  case $signing_dir in "$RS"|"$RS"/*) die "the Android keystore must live outside the repository ($keystore)" ;; esac
  # Also outside a repository this one is checked out in (as a submodule).
  super=$(git -C "$RS" rev-parse --show-superproject-working-tree 2> /dev/null || true)
  if [ -n "$super" ]; then
    case $signing_dir in "$super"|"$super"/*) die "the Android keystore must live outside the repository ($keystore is inside $super)" ;; esac
  fi
  [ "$(dirname "$password_file")" = "$signing_dir" ] || die "keep the keystore password file next to the keystore ($signing_dir)"
  generate=0
  if [ ! -f "$keystore" ]; then
    generate=1
    mkdir -p "$signing_dir"
    chmod 700 "$signing_dir"
  fi
  use_emulator=0
  if [ "$emulator" != 0 ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    use_emulator=1
  elif [ "$emulator" = 1 ]; then
    die "--emulator needs a usable /dev/kvm"
  fi
  need_disk $(($(estimate 8 2 "$PREFIX-target-android") + use_emulator * $(estimate 5 1 "$PREFIX-android-emulator")))
  set -- -v "$signing_dir:/signing" \
    -e HELIX_ANDROID_KEYSTORE="/signing/$(basename "$keystore")" \
    -e HELIX_ANDROID_KEYSTORE_PASSWORD_FILE="/signing/$(basename "$password_file")" \
    -e HELIX_ANDROID_KEY_ALIAS="$alias" \
    -e HELIX_ANDROID_GENERATE="$generate" \
    -v "$PREFIX-gradle:/cache/gradle"
  if [ "$use_emulator" = 1 ]; then
    set -- "$@" --device /dev/kvm -e HELIX_EMULATOR=1 \
      -e ANDROID_EMULATOR_IMAGE="$ANDROID_EMULATOR_IMAGE" \
      -v "$PREFIX-android-emulator:/opt/android-emu"
  fi
  status=0
  run_in android linux/amd64 "$@" -- build/scripts/android.sh || status=$?
  # Printed even when the build failed after the key was created.
  if [ "$generate" = 1 ] && [ -f "$keystore" ]; then
    cat >&2 <<EOF

################################################################################
#  A NEW ANDROID RELEASE SIGNING KEY WAS CREATED:
#      $keystore
#      $password_file   (its password, mode 0600)
#  BACK BOTH UP NOW (offline, e.g. an encrypted USB stick or password manager).
#  Every future update of the app must be signed with this same key: if it is
#  lost, installed apps can never be updated, only uninstalled and replaced.
#  Never commit it; it is outside the repository on purpose.
################################################################################

EOF
  fi
  return "$status"
}

native_apple() {
  [ "$(uname -s)" = Darwin ] || {
    cat >&2 <<EOF
build.sh: '$platform' cannot be built here. Apple's toolchains (Xcode, the macOS
and iOS SDKs, codesign) run only on macOS, and no container can provide them.
Run this same command on a Mac with Xcode, Rust ($RUST_TOOLCHAIN via rustup) and
Node $NODE_VERSION:
    $0 $platform$( [ "$release" = 1 ] && printf ' --release')
EOF
    exit 3
  }
  take_lock
  do_cleanup=1
  need_disk 6
  # Build caches of their own (removed by the cleanup), not the user's ~/.cargo, ~/.npm or target/.
  NATIVE_CACHE=$RS/.build-cache
  HELIX_RELEASE=$release HELIX_OUT=$out NODE_VERSION=$NODE_VERSION RUST_TOOLCHAIN=$RUST_TOOLCHAIN \
    CARGO_HOME=$NATIVE_CACHE/cargo CARGO_TARGET_DIR=$NATIVE_CACHE/target npm_config_cache=$NATIVE_CACHE/npm \
    sh "$RS/build/scripts/apple.sh" "$platform"
}

# List what a multi-platform build produced.
report_outputs() {
  say "done. Release files (with .sha256 and SHA256SUMS) are in $RS/dist:"
  for dir in "$RS"/dist/linux "$RS"/dist/windows "$RS"/dist/android "$RS"/dist/macos "$RS"/dist/ios; do
    [ -d "$dir" ] || continue
    for file in "$dir"/*; do
      case $file in *.sha256|*/SHA256SUMS|*"/*") continue ;; esac
      [ -f "$file" ] && printf '    %s\n' "${file#"$RS"/}" >&2
    done
  done
}

case $platform in
  linux|cli-linux|windows|cli-windows|android|all|all-linux-host|test) need_docker; take_lock; do_cleanup=1 ;;
esac

case $platform in
  linux) container_linux app ;;
  cli-linux) container_linux cli ;;
  windows) container_windows app ;;
  cli-windows) container_windows cli ;;
  android) container_android ;;
  all|all-linux-host)
    [ -z "$out" ] || die "$platform writes to dist/<platform>; --out is not supported"
    say "building linux, windows and android in containers"
    container_linux app
    container_windows app
    container_android
    if [ "$platform" = all ]; then
      if [ "$(uname -s)" = Darwin ]; then
        platform=macos
        native_apple
        if [ -n "${APPLE_DEVELOPMENT_TEAM:-}" ]; then
          platform=ios
          native_apple
        else
          say "ios skipped: set APPLE_DEVELOPMENT_TEAM to build it too (it is never published)"
        fi
      else
        say "macos and ios skipped: they build only on a Mac (run build.sh all there)"
      fi
    fi
    report_outputs
    ;;
  test)
    need_disk 6
    run_in linux linux/amd64 -e HELIX_TEST_PARTS="${HELIX_TEST_PARTS:-}" -- build/scripts/test.sh
    ;;
  macos|ios) native_apple ;;
  images)
    need_docker
    take_lock
    for kind in linux windows android; do
      image=$(image_for "$kind" linux/amd64) || exit 1
      say "image: $image"
    done
    ;;
  clean)
    need_docker
    take_lock
    keep_cache=0
    NATIVE_CACHE=$RS/.build-cache
    cleanup
    ;;
  *) usage ;;
esac
