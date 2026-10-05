#!/bin/zsh
#
#  community-sign.sh
#  Mac Monitor
#
#  Ad-hoc signs a Mac Monitor build produced with Community.xcconfig so that it
#  can be loaded in a virtual machine with SIP disabled and
#  `amfi_get_out_of_my_way=1` set. The signature carries the real entitlements
#  and identifiers; only the certificate chain is missing. Such a build will
#  NOT load on a normally configured Mac.
#
#  Author: Brandon Dalton
#  Co-author: Claude
#
#  Usage: community-sign.sh "/path/to/Mac Monitor.app"
#

set -euo pipefail
# Absolute tool paths so the script behaves the same from Xcode, a terminal, or CI.
CODESIGN=/usr/bin/codesign
GREP=/usr/bin/grep

if [[ $# -ne 1 || ! -d "$1" ]]; then
    echo "usage: $0 \"/path/to/Mac Monitor.app\"" >&2
    exit 64
fi

APP="$1"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_ENTITLEMENTS="$PROJECT_DIR/ProjectSutro/ProjectSutro.entitlements"
SYSEXT_ENTITLEMENTS="$PROJECT_DIR/SecurityExtension/SecurityExtension.entitlements"

SYSEXT="$APP/Contents/Library/SystemExtensions/com.swiftlydetecting.agent.securityextension.systemextension"
# The framework is embedded twice: once in the app, once inside the extension.
SYSEXT_FRAMEWORK="$SYSEXT/Contents/Frameworks/SutroESFramework.framework"
APP_FRAMEWORK="$APP/Contents/Frameworks/SutroESFramework.framework"
# The command line tool. No entitlements: it only talks to the extension.
CLI="$APP/Contents/MacOS/macmonitor"

for path in "$SYSEXT_FRAMEWORK" "$APP_FRAMEWORK" "$SYSEXT" "$CLI" "$APP_ENTITLEMENTS" "$SYSEXT_ENTITLEMENTS"; do
    [[ -e "$path" ]] || { echo "missing: $path" >&2; exit 66; }
done

# codesign reports every --force re-sign on stderr; that is expected here, so hide only that line.
sign() {
    "$CODESIGN" --force --sign - --timestamp=none "$@" 2> >("$GREP" -v "replacing existing signature" >&2)
}

# Sign from the inside out. Each outer signature seals the inner ones.
echo "→ framework (inside security extension)"
sign "$SYSEXT_FRAMEWORK"

echo "→ security extension"
sign \
    --identifier com.swiftlydetecting.agent.securityextension \
    --entitlements "$SYSEXT_ENTITLEMENTS" "$SYSEXT"

echo "→ framework (inside app)"
sign "$APP_FRAMEWORK"

# The extension only streams to a peer signed with this identifier (SensorXPC.commandLineRequirement).
echo "→ command line tool"
sign --identifier com.swiftlydetecting.agent.cli "$CLI"

echo "→ app"
sign \
    --identifier com.swiftlydetecting.agent \
    --entitlements "$APP_ENTITLEMENTS" "$APP"

echo "→ verify"
"$CODESIGN" --verify --deep --strict --verbose=1 "$APP"
"$CODESIGN" --display --entitlements - "$SYSEXT" 2>&1 | "$GREP" -q endpoint-security.client \
    || { echo "security extension lost its ES entitlement" >&2; exit 70; }
# grep reads every line (no -q), so codesign never writes into a closed pipe under pipefail.
[[ "$("$CODESIGN" --display --verbose=1 "$CLI" 2>&1 | "$GREP" "^Identifier=")" == \
    "Identifier=com.swiftlydetecting.agent.cli" ]] || { echo "macmonitor lost its signing identifier" >&2; exit 70; }
echo "✅ ad-hoc signed: $APP"
