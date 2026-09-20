#!/bin/zsh
#
#  community-build.sh
#  Mac Monitor
#
#  One-shot build for contributors without Swiftly Detecting's signing
#  certificates. Builds the "Community" configuration (see Community.xcconfig)
#  and ad-hoc signs the result with Scripts/community-sign.sh.
#
#  The output loads only in a virtual machine with SIP disabled and
#  `amfi_get_out_of_my_way=1` in boot-args. See the "Community development"
#  wiki page.
#
#  Author: Brandon Dalton
#  Co-author: Claude
#
#  Usage: community-build.sh
#  Output: build/MacMonitor-community.zip
#

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DERIVED_DATA="$PROJECT_DIR/build/DerivedData-community"
APP="$DERIVED_DATA/Build/Products/Community/Mac Monitor.app"

/usr/bin/xcodebuild \
    -project "$PROJECT_DIR/ProjectSutro.xcodeproj" \
    -scheme "ProjectSutro" \
    -configuration Community \
    -derivedDataPath "$DERIVED_DATA" \
    build | /usr/bin/grep -E "error:|warning: .*(sign|entitle)|BUILD (SUCCEEDED|FAILED)" || true

[[ -d "$APP" ]] || { echo "build did not produce $APP" >&2; exit 1; }

"$PROJECT_DIR/Scripts/community-sign.sh" "$APP"

# Zip with ditto so the ad-hoc signature survives the copy into the VM.
ZIP="$PROJECT_DIR/build/MacMonitor-community.zip"
/bin/rm -f "$ZIP"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"

echo
echo "Copy this into your SIP-off VM and extract it into /Applications:"
echo "  $ZIP"
