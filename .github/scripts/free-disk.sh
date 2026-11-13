#!/bin/sh
# Free disk space on a GitHub-hosted Ubuntu runner before a container build:
# the preinstalled SDKs and images below are not used by build.sh (it brings
# its own toolchains in its images). Only for CI runners.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ] || { echo "free-disk.sh: only for GitHub-hosted runners" >&2; exit 1; }
df -h /
sudo rm -rf \
  /usr/share/dotnet \
  /usr/local/lib/android \
  /opt/ghc \
  /usr/local/.ghcup \
  /opt/hostedtoolcache/CodeQL \
  /usr/local/share/boost \
  /usr/share/swift \
  /usr/local/share/powershell \
  /usr/local/share/chromium \
  /usr/lib/jvm \
  /opt/microsoft \
  /opt/google
docker image prune --all --force > /dev/null || true
df -h /
