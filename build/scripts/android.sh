#!/bin/sh
# Android build (inside build/docker/android.Dockerfile): one universal APK
# for arm64-v8a (phones) and x86_64 (the emulator), signed with the release
# keystore mounted at /signing (generated there on first use), then verified
# with apksigner and aapt2 (package, version, ABIs, the intent filter of the
# anubisauto:// and legacy awakehelix:// links). With HELIX_EMULATOR=1 and
# /dev/kvm, an emulator boots, installs the APK and opens both kinds of link.
#   build/scripts/android.sh
. "$(dirname "$0")/common.sh"

keystore=${HELIX_ANDROID_KEYSTORE:-/signing/android-release.jks}
password_file=${HELIX_ANDROID_KEYSTORE_PASSWORD_FILE:-/signing/android-release.password}
alias=${HELIX_ANDROID_KEY_ALIAS:-}

check_attestation
out=$(out_dir android)

if [ ! -f "$keystore" ]; then
  [ "${HELIX_ANDROID_GENERATE:-0}" = 1 ] || die "release keystore $keystore is missing (build.sh generates it on first use)"
  say "generating the Android release keystore $keystore"
  alias=${alias:-$NAME}
  umask 077
  if [ ! -s "$password_file" ]; then
    head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | cut -c1-40 > "$password_file"
  fi
  keytool -genkeypair -keystore "$keystore" -storetype PKCS12 -alias "$alias" \
    -keyalg RSA -keysize 4096 -validity 10000 \
    -dname "CN=Anubis Automation Script Signer, O=Sivilization" \
    -storepass:file "$password_file" -keypass:file "$password_file" > /dev/null 2>&1
  chmod 600 "$keystore" "$password_file"
  umask 022
fi
[ -s "$password_file" ] || die "keystore password file $password_file is missing or empty"
if [ -z "$alias" ]; then
  # No alias given: the keystore's only key (keystores made before 0.7.0
  # name it after the former app, so it is read rather than assumed).
  alias=$(keytool -list -keystore "$keystore" -storetype PKCS12 -storepass:file "$password_file" 2> /dev/null |
    sed -n 's/^\([^,]*\), .*PrivateKeyEntry.*$/\1/p')
  if [ -z "$alias" ] || [ "$(printf '%s\n' "$alias" | wc -l)" -ne 1 ]; then
    die "set HELIX_ANDROID_KEY_ALIAS: $keystore does not hold exactly one key (or the password is wrong)"
  fi
  say "release key alias $alias (the keystore's only key)"
fi
# SHA-256 of the release certificate, to check the APK's signer against.
release_cert=$(keytool -list -v -keystore "$keystore" -storetype PKCS12 -storepass:file "$password_file" -alias "$alias" 2> /dev/null |
  sed -n 's/^[[:space:]]*SHA256: //p' | head -n 1 | tr -d ':' | tr 'A-F' 'a-f')
[ -n "$release_cert" ] || die "no key $alias in $keystore (or the password is wrong)"
export HELIX_ANDROID_KEYSTORE="$keystore" HELIX_ANDROID_KEYSTORE_PASSWORD_FILE="$password_file" HELIX_ANDROID_KEY_ALIAS="$alias"

frontend
cd app || exit 1
# A project generated before the identifier changed builds the wrong package: start over.
if [ -f src-tauri/gen/android/app/build.gradle.kts ] && ! grep -qF "\"$IDENTIFIER\"" src-tauri/gen/android/app/build.gradle.kts; then
  say "src-tauri/gen/android is for another app identifier: generating it again for $IDENTIFIER"
  rm -rf src-tauri/gen/android
fi
if [ ! -f src-tauri/gen/android/app/build.gradle.kts ]; then
  say "tauri android init"
  npx tauri android init --ci --skip-targets-install
  # Re-run so `tauri icon` also writes the Android launcher icons (mipmaps).
  npm run --silent icons > /dev/null
fi
node scripts/android-signing.mjs src-tauri/gen/android
# Tauri's template enables Gradle's configuration cache, which runs the per-ABI
# Rust tasks in parallel; the two `android-studio-script` runs then race on
# jniLibs and an ABI's library can be missing from the APK. Build them in turn.
props=src-tauri/gen/android/gradle.properties
if grep -q '^org.gradle.configuration-cache=' "$props"; then
  sed -i 's/^org.gradle.configuration-cache=.*/org.gradle.configuration-cache=false/' "$props"
else
  printf '\norg.gradle.configuration-cache=false\n' >> "$props"
fi
grep -q '^org.gradle.parallel=true' "$props" && die "$props enables org.gradle.parallel; the per-ABI Rust tasks must run in turn"
say "app: tauri android build --apk --target aarch64 --target x86_64 ($PROFILE)"
# shellcheck disable=SC2086
npx tauri android build $TAURI_PROFILE_FLAG --apk --target aarch64 --target x86_64 --ci
cd .. || exit 1
apk=$(ls app/src-tauri/gen/android/app/build/outputs/apk/universal/"$PROFILE"/*.apk | head -n 1)
[ -f "$apk" ] || die "no APK produced"

say "verify: apksigner"
apksigner verify --verbose --print-certs "$apk" | tee /tmp/apksigner.txt | grep -E 'Verified using|Signer #1 certificate (DN|SHA-256)'
grep -q 'Verifies' /tmp/apksigner.txt || die "apksigner did not verify the APK"
if [ "$HELIX_RELEASE" = 1 ]; then
  signer_cert=$(sed -n 's/^Signer #1 certificate SHA-256 digest: //p' /tmp/apksigner.txt | head -n 1 | tr 'A-F' 'a-f')
  [ "$signer_cert" = "$release_cert" ] || die "the APK is not signed with the release keystore ($signer_cert, not $release_cert)"
fi
say "verify: aapt2 badging and manifest"
aapt2 dump badging "$apk" > /tmp/badging.txt
grep -E "^package:|^sdkVersion|^targetSdkVersion|^native-code|^application-label:" /tmp/badging.txt
grep -q "package: name='$IDENTIFIER'" /tmp/badging.txt || die "package name is not $IDENTIFIER"
grep -q "versionName='$APP_VERSION'" /tmp/badging.txt || die "versionName is not $APP_VERSION"
grep -q "native-code: .*'arm64-v8a'" /tmp/badging.txt || die "no arm64-v8a library in the APK"
grep -q "native-code: .*'x86_64'" /tmp/badging.txt || die "no x86_64 library in the APK"
aapt2 dump xmltree --file AndroidManifest.xml "$apk" > /tmp/manifest.txt
for scheme in $SCHEMES; do
  grep -q "\"$scheme\"" /tmp/manifest.txt || die "the manifest has no $scheme:// intent filter"
done
grep -q 'android.intent.category.BROWSABLE' /tmp/manifest.txt || die "the link intent filter is not BROWSABLE"
cp "$apk" "$out/$(release_name android-universal.apk)"

if [ "${HELIX_EMULATOR:-0}" = 1 ]; then
  sh build/scripts/android-emulator.sh "$apk" "$IDENTIFIER"
fi
checksums "$out"
