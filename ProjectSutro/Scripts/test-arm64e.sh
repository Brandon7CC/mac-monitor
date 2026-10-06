#!/bin/zsh
#
#  test-arm64e.sh
#  Mac Monitor
#
#  Runs SutroESFramework's tests in an arm64e process with pointer
#  authentication on. xcodebuild test can't: Xcode's test runner (xctest) has
#  only x86_64 and arm64 slices, so it runs the tests with pointer
#  authentication off (from macOS 14.4, on their and the framework's arm64e
#  slices). This builds the tests (the scheme tests in Community, which
#  builds arm64 and arm64e on Apple silicon), builds arm64e-test-host.m
#  against Xcode's XCTest, and runs every test in it.
#
#  Needs Apple silicon on macOS 26 or later, the first to run arm64e with
#  pointer authentication on. The host refuses to run the tests with it off,
#  or on a framework that isn't the arm64e slice just built.
#
#  Created by Brandon Dalton on 10/5/26.
#
#  Usage: test-arm64e.sh [TestClass | TestClass/testMethod]
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DERIVED_DATA="${DERIVED_DATA:-$PROJECT_DIR/build/DerivedData-arm64e-tests}"
PRODUCTS="$DERIVED_DATA/Build/Products/Community"
HOST="$DERIVED_DATA/arm64e-test-host"
DEVELOPER="$(/usr/bin/xcrun --sdk macosx --show-sdk-platform-path)/Developer"
LOG="$(/usr/bin/mktemp)"
trap '/bin/rm -f "$LOG"' EXIT

[[ "$(/usr/bin/uname -m)" == arm64 ]] || { echo "arm64e needs Apple silicon" >&2; exit 69; }

if ! /usr/bin/xcodebuild build-for-testing \
    -project "$PROJECT_DIR/ProjectSutro.xcodeproj" \
    -scheme SutroESFramework \
    -destination 'platform=macOS' \
    -derivedDataPath "$DERIVED_DATA" \
    > "$LOG" 2>&1; then
    /usr/bin/grep -E "error:" "$LOG" >&2 || /usr/bin/tail -20 "$LOG" >&2
    echo "The tests didn't build." >&2
    exit 1
fi

# XCTest is in the platform's Developer folder, which a test runner otherwise finds for it.
/usr/bin/xcrun --sdk macosx clang -arch arm64e -mmacosx-version-min=14.0 -fobjc-arc -fmodules \
    -F "$DEVELOPER/Library/Frameworks" -framework XCTest \
    -Wl,-rpath,"$DEVELOPER/Library/Frameworks" \
    -Wl,-rpath,"$DEVELOPER/Library/PrivateFrameworks" \
    -Wl,-rpath,"$DEVELOPER/usr/lib" \
    "$PROJECT_DIR/Scripts/arm64e-test-host.m" -o "$HOST"

# The tests find SutroESFramework where it was built, as xcodebuild test has them do.
DYLD_FRAMEWORK_PATH="$PRODUCTS" DYLD_LIBRARY_PATH="$PRODUCTS" \
    "$HOST" "$PRODUCTS/SutroESFrameworkTests.xctest" "$@"
