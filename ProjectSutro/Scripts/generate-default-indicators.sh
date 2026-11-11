#!/bin/zsh
#
#  generate-default-indicators.sh
#  Mac Monitor
#
#  Regenerates SutroESFramework/Detection/DefaultIndicators.json, the indicators
#  Mac Monitor ships, from the test target's source
#  (SutroESFrameworkTests/Default Indicators/Source), by running the file's
#  generator test with MM_WRITE_DEFAULT_INDICATORS=1, which writes the file
#  instead of comparing it. The linker copies the file into the framework's
#  binary, so build again afterwards, and commit the file.
#
#  Author: Brandon Dalton
#
#  Usage: generate-default-indicators.sh
#  Output: SutroESFramework/Detection/DefaultIndicators.json
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_DIR="$(cd "$PROJECT_DIR/.." && pwd)"
DERIVED_DATA="${DERIVED_DATA:-$PROJECT_DIR/build/DerivedData-indicators}"
FILE="$PROJECT_DIR/SutroESFramework/Detection/DefaultIndicators.json"
LOG="$(/usr/bin/mktemp)"
trap '/bin/rm -f "$LOG"' EXIT

# xcodebuild hands TEST_RUNNER_-prefixed variables to the test process without the prefix.
if ! TEST_RUNNER_MM_WRITE_DEFAULT_INDICATORS=1 /usr/bin/xcodebuild test \
    -project "$PROJECT_DIR/ProjectSutro.xcodeproj" \
    -scheme SutroESFramework \
    -destination 'platform=macOS' \
    -derivedDataPath "$DERIVED_DATA" \
    -only-testing:SutroESFrameworkTests/DefaultIndicatorFileTests/testCommittedFileIsGenerated \
    > "$LOG" 2>&1; then
    /usr/bin/grep -E "error:" "$LOG" >&2 || /usr/bin/tail -20 "$LOG" >&2
    echo "The generator didn't run: $FILE is unchanged." >&2
    exit 1
fi

/usr/bin/git -C "$REPO_DIR" diff --stat -- "$FILE"
