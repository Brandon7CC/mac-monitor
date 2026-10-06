#!/bin/zsh
#
#  generate-telemetry-schema.sh
#  Mac Monitor
#
#  Regenerates Schema/mac-monitor-telemetry.schema.json from the test target's
#  description of the export (SutroESFrameworkTests/Telemetry Schema/Source),
#  by running the schema's generator test with MM_WRITE_SCHEMA=1, which writes
#  the file instead of comparing it. Commit Schema/ afterwards.
#
#  Author: Brandon Dalton
#
#  Usage: generate-telemetry-schema.sh
#  Output: Schema/mac-monitor-telemetry.schema.json
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_DIR="$(cd "$PROJECT_DIR/.." && pwd)"
DERIVED_DATA="${DERIVED_DATA:-$PROJECT_DIR/build/DerivedData-schema}"
LOG="$(/usr/bin/mktemp)"
trap '/bin/rm -f "$LOG"' EXIT

# xcodebuild hands TEST_RUNNER_-prefixed variables to the test process without the prefix.
if ! TEST_RUNNER_MM_WRITE_SCHEMA=1 /usr/bin/xcodebuild test \
    -project "$PROJECT_DIR/ProjectSutro.xcodeproj" \
    -scheme SutroESFramework \
    -destination 'platform=macOS' \
    -derivedDataPath "$DERIVED_DATA" \
    -only-testing:SutroESFrameworkTests/TelemetrySchemaFileTests/testCommittedSchemaIsGenerated \
    > "$LOG" 2>&1; then
    /usr/bin/grep -E "error:" "$LOG" >&2 || /usr/bin/tail -20 "$LOG" >&2
    echo "The generator didn't run: Schema/ is unchanged." >&2
    exit 1
fi

/usr/bin/git -C "$REPO_DIR" diff --stat -- Schema/
