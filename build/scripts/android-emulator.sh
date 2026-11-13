#!/bin/sh
# Optional Android smoke test (needs /dev/kvm): install the emulator and one
# x86_64 system image into a second SDK root on the volume mounted at
# /opt/android-emu (kept between builds), boot a headless emulator, install
# the APK, open awakehelix://grants with it and check that our activity
# handled the link and the app process runs. Saves a screenshot next to the APK.
#   build/scripts/android-emulator.sh <apk> <package>
. "$(dirname "$0")/common.sh"

apk=$1
package=$2
image=${ANDROID_EMULATOR_IMAGE:-system-images;android-34;default;x86_64}
emu=/opt/android-emu
[ -c /dev/kvm ] || die "/dev/kvm is not available in the container"

say "emulator: installing the emulator and $image into $emu (cached in a volume)"
mkdir -p "$emu"
cp -r /opt/android-sdk/licenses "$emu/"
# The emulator wants platform-tools in its SDK root: share the image's.
[ -e "$emu/platform-tools" ] || ln -s /opt/android-sdk/platform-tools "$emu/platform-tools"
sdkmanager --sdk_root="$emu" --install emulator "$image" > /dev/null
export ANDROID_SDK_ROOT="$emu" ANDROID_HOME="$emu" ANDROID_AVD_HOME=/tmp/avd
export PATH="$emu/emulator:$PATH"
# avdmanager only knows its own SDK root, so write the AVD by hand.
sysdir=$(printf '%s' "$image" | tr ';' '/')
api=$(printf '%s' "$image" | cut -d';' -f2)
mkdir -p "$ANDROID_AVD_HOME/helix.avd"
printf 'avd.ini.encoding=UTF-8\npath=%s/helix.avd\ntarget=%s\n' "$ANDROID_AVD_HOME" "$api" > "$ANDROID_AVD_HOME/helix.ini"
cat > "$ANDROID_AVD_HOME/helix.avd/config.ini" <<AVD
image.sysdir.1=$sysdir/
abi.type=x86_64
hw.cpu.arch=x86_64
hw.cpu.ncore=2
hw.ramSize=2048
hw.lcd.width=720
hw.lcd.height=1440
hw.lcd.density=320
hw.gpu.enabled=yes
hw.gpu.mode=swiftshader_indirect
hw.keyboard=yes
disk.dataPartition.size=2G
PlayStore.enabled=false
tag.id=default
AVD

say "emulator: booting (headless)"
emulator -avd helix -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect \
  -memory 2048 -cores 2 -wipe-data -no-metrics > /tmp/emulator.log 2>&1 &
emulator_pid=$!
trap 'adb emu kill > /dev/null 2>&1 || kill $emulator_pid 2> /dev/null || true' EXIT
booted=0
for _ in $(seq 1 180); do
  kill -0 "$emulator_pid" 2> /dev/null || { tail -n 20 /tmp/emulator.log >&2; die "the emulator exited"; }
  if [ "$(adb shell getprop sys.boot_completed 2> /dev/null | tr -d '\r')" = 1 ]; then booted=1; break; fi
  sleep 2
done
[ "$booted" = 1 ] || { tail -n 40 /tmp/emulator.log >&2; die "the emulator did not boot in 6 minutes"; }
adb shell input keyevent 82 > /dev/null 2>&1 || true

say "emulator: adb install"
adb install -r "$apk"
say "emulator: open awakehelix://grants"
adb shell am start -W -a android.intent.action.VIEW -d "awakehelix://grants" | tee /tmp/am-start.txt
grep -q "$package" /tmp/am-start.txt || die "awakehelix:// did not open $package"
sleep 15
adb shell pidof "$package" > /dev/null || die "$package is not running after opening the link"
adb exec-out screencap -p > "$(dirname "$apk")/emulator-grants.png" || true
adb shell dumpsys activity activities | grep -m1 -E "mResumedActivity|topResumedActivity" || true
say "emulator: the APK installs, handles awakehelix:// and runs"
