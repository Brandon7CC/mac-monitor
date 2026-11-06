#!/bin/zsh
#
#  test-performance.sh
#  Mac Monitor
#
#  Runs SutroESFramework's benchmarks (every PerformanceTestCase in
#  SutroESFrameworkTests) on an optimized build, and writes a results file
#  tagged with this Mac (hw.model, chip, cores), its macOS build and the Mac
#  Monitor version and commit: JSON, and a CSV beside it.
#
#  The tests build in Community, which Xcode compiles unoptimized (-Onone).
#  This builds them with -O and whole-module optimization instead, as Release
#  ships, into a DerivedData folder of their own. Only the active
#  architecture is built: xcodebuild runs the tests' arm64 slice, not the
#  arm64e one Mac Monitor ships (see test-arm64e.sh).
#
#  Compare two results files with compare-performance.js. For numbers worth
#  comparing, run on power, with Low Power Mode off and little else running:
#  each file records the thermal state and Low Power Mode it started in.
#
#  Created by Brandon Dalton on 11/5/26.
#
#  Usage: test-performance.sh [-o results.json] [-s samples] [TestClass | TestClass/testMethod ...]
#
#    -o  The results file. By default build/Performance/<time>-<model>-<version>.json.
#    -s  Samples per benchmark, 10 by default.
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DERIVED_DATA="${DERIVED_DATA:-$PROJECT_DIR/build/DerivedData-performance}"
LOG="$(/usr/bin/mktemp)"
trap '/bin/rm -f "$LOG"' EXIT

RESULTS="" SAMPLES=10
while getopts "o:s:" option; do
    case "$option" in
        o) RESULTS="$OPTARG" ;;
        s) SAMPLES="$OPTARG" ;;
        *) /usr/bin/sed -n 's/^#  Usage: /Usage: /p' "$0" >&2; exit 64 ;;
    esac
done
shift $((OPTIND - 1))

MODEL="$(/usr/sbin/sysctl -n hw.model)"
VERSION="$(/usr/bin/xcodebuild -project "$PROJECT_DIR/ProjectSutro.xcodeproj" -target SutroESFramework \
    -showBuildSettings 2>/dev/null | /usr/bin/awk '$1 == "MARKETING_VERSION" { print $3; exit }')"
COMMIT="$(/usr/bin/git -C "$PROJECT_DIR" describe --always --dirty --abbrev=12 2>/dev/null || echo unknown)"
RESULTS="${RESULTS:-$PROJECT_DIR/build/Performance/$(/bin/date +%Y%m%d-%H%M%S)-${MODEL//,/-}-$VERSION.json}"
/bin/mkdir -p "$(dirname "$RESULTS")"
RESULTS="$(cd "$(dirname "$RESULTS")" && pwd)/$(basename "$RESULTS")"

# Every benchmark class, unless the arguments name some.
TESTS=("$@")
if (( ${#TESTS} == 0 )); then
    TESTS=($(/usr/bin/grep -rhoE "class [A-Za-z]+: PerformanceTestCase" "$PROJECT_DIR/SutroESFrameworkTests" \
        | /usr/bin/awk '{ sub(":", "", $2); print $2 }' | /usr/bin/sort -u))
fi
ONLY=()
for test in "${TESTS[@]}"; do ONLY+=("-only-testing:SutroESFrameworkTests/$test"); done

XCODEBUILD=(/usr/bin/xcodebuild -project "$PROJECT_DIR/ProjectSutro.xcodeproj" -scheme SutroESFramework
    -destination 'platform=macOS' -derivedDataPath "$DERIVED_DATA")

echo "Building the benchmarks (-O, whole module)..."
if ! "${XCODEBUILD[@]}" build-for-testing ONLY_ACTIVE_ARCH=YES SWIFT_OPTIMIZATION_LEVEL=-O \
    SWIFT_COMPILATION_MODE=wholemodule GCC_OPTIMIZATION_LEVEL=s > "$LOG" 2>&1; then
    /usr/bin/grep -E "error:" "$LOG" >&2 || /usr/bin/tail -20 "$LOG" >&2
    echo "The benchmarks didn't build." >&2
    exit 1
fi

echo "Running ${#TESTS} benchmark classes on $MODEL ($(/usr/sbin/sysctl -n machdep.cpu.brand_string))..."
STATUS=0
TEST_RUNNER_SUTRO_PERFORMANCE=1 \
TEST_RUNNER_SUTRO_PERFORMANCE_SAMPLES="$SAMPLES" \
TEST_RUNNER_SUTRO_PERFORMANCE_RESULTS="$RESULTS" \
TEST_RUNNER_SUTRO_PERFORMANCE_CONFIGURATION="Community -O" \
TEST_RUNNER_SUTRO_PERFORMANCE_COMMIT="$COMMIT" \
    "${XCODEBUILD[@]}" test-without-building -parallel-testing-enabled NO "${ONLY[@]}" > "$LOG" 2>&1 || STATUS=$?

/usr/bin/sed -nE 's/^\[performance\] (.*)$/  \1/p' "$LOG" | /usr/bin/grep -v "  Results: "
if (( STATUS != 0 )); then
    /usr/bin/grep -E "error:|failed" "$LOG" >&2 || /usr/bin/tail -20 "$LOG" >&2
    echo "Some benchmarks failed: the results file has the others." >&2
fi
[[ -f "$RESULTS" ]] || { echo "No results were written." >&2; exit 1; }
echo "Results: $RESULTS"
echo "     and ${RESULTS%.json}.csv"
echo "Compare: $PROJECT_DIR/Scripts/compare-performance.js <before.json> $RESULTS"
exit $STATUS
