#!/bin/zsh
#
#  link-indicator-pack.sh
#  Mac Monitor
#
#  Copies a signed indicator pack, a release of the indicators repository
#  (its dist/mac-monitor-indicators.json), to
#  SutroESFramework/Indicators/LinkedIndicatorPack.json, the pack a build
#  links in. Its indicators become the ones Mac Monitor ships, and a pack
#  installed later must be a later release. The linker copies the file into
#  the framework's binary, so build again afterwards, run the tests, which
#  verify its signature, and commit the file.
#
#  Author: Brandon Dalton
#
#  Usage: link-indicator-pack.sh SIGNED_PACK
#  Output: SutroESFramework/Indicators/LinkedIndicatorPack.json
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
REPO_DIR="$(cd "$PROJECT_DIR/.." && pwd)"
FILE="$PROJECT_DIR/SutroESFramework/Indicators/LinkedIndicatorPack.json"

if [[ $# -ne 1 || ! -f "$1" ]]; then
    echo "Usage: link-indicator-pack.sh SIGNED_PACK" >&2
    exit 64
fi

# The sequence of a signed pack's file, or nothing for a file that isn't one.
sequence() {
    /usr/bin/python3 -I -c '
import base64, json, sys
file = json.load(open(sys.argv[1]))
if not file.get("signature"):
    sys.exit(1)
print(json.loads(base64.b64decode(file["payload"]))["pack"]["sequence"])
' "$1" 2>/dev/null
}

if ! offered="$(sequence "$1")" || [[ "$offered" -lt 1 ]]; then
    echo "$1 isn't a signed release of the indicators repository." >&2
    exit 65
fi
if current="$(sequence "$FILE")" && [[ "$offered" -lt "$current" ]]; then
    echo "$1 is pack $offered, older than pack $current, which is linked now." >&2
    exit 65
fi

/bin/cp "$1" "$FILE"
echo "Linked pack $offered. Build, run the tests, and commit:"
/usr/bin/git -C "$REPO_DIR" diff --stat -- "$FILE"
