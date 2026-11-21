#!/bin/zsh
#
#  verify-build.sh
#  Mac Monitor
#
#  Verifies a built Mac Monitor.app. Every Mach-O in the bundle needs each requested architecture, and each slice's
#  minimum macOS has to match LSMinimumSystemVersion in Info.plist. The code signature has to verify and
#  macmonitor --version has to run.
#
#  Debug builds only include the active architecture. On an M4 with macOS 26 or later that's arm64e, which macOS 13
#  won't load ("Library missing ... have 'arm64e', need 'arm64'").
#
#  Author: Brandon Dalton
#
#  Usage: verify-build.sh "/path/to/Mac Monitor.app" [architecture ...]
#         Checks arm64 and arm64e by default. Pass x86_64 arm64 arm64e to check a release build.
#

set -euo pipefail
# Use absolute tool paths. grep and ls may be shell functions or aliases.
LIPO=/usr/bin/lipo
VTOOL=/usr/bin/vtool
CODESIGN=/usr/bin/codesign
FILE=/usr/bin/file
GREP=/usr/bin/grep
PLISTBUDDY=/usr/libexec/PlistBuddy

if [[ $# -lt 1 || ! -d "$1" ]]; then
    echo "usage: $0 \"/path/to/Mac Monitor.app\" [architecture ...]" >&2
    exit 64
fi

APP="$1"
shift
REQUIRED=("$@")
(( ${#REQUIRED} )) || REQUIRED=(arm64 arm64e)
MINIMUM=$("$PLISTBUDDY" -c "Print LSMinimumSystemVersion" "$APP/Contents/Info.plist")
failures=0

# Report a failure and keep checking, so one run lists every problem.
fail() {
    echo "❌ $1" >&2
    failures=$((failures + 1))
}

echo "Checking $APP: ${REQUIRED[*]}, macOS $MINIMUM or later"
while IFS= read -r -d '' binary; do
    "$FILE" -b "$binary" | "$GREP" -q "Mach-O" || continue
    name="${binary#$APP/}"
    archs=($("$LIPO" -archs "$binary"))
    for arch in $REQUIRED; do
        (( ${archs[(Ie)$arch]} )) || fail "$name has no $arch slice (it has ${archs[*]})"
    done
    for arch in $archs; do
        minos=$("$VTOOL" -arch "$arch" -show-build "$binary" 2>/dev/null | /usr/bin/awk '/minos/ {print $2; exit}')
        [[ "$minos" == "$MINIMUM" ]] || fail "$name's $arch slice needs macOS ${minos:-?}, the app says $MINIMUM"
    done
done < <(/usr/bin/find "$APP" -type f -perm -111 -print0)

"$CODESIGN" --verify --deep --strict "$APP" 2>/dev/null || fail "The signature doesn't verify"
"$APP/Contents/MacOS/macmonitor" --version >/dev/null 2>&1 || fail "macmonitor --version doesn't run here"

if (( failures > 0 )); then
    echo "❌ $failures problem(s)" >&2
    exit 1
fi
echo "✅ Every Mach-O has ${REQUIRED[*]} for macOS $MINIMUM, the signature verifies, and macmonitor runs"
