#!/bin/zsh
#
#  attach-telemetry-schema.sh
#  Mac Monitor
#
#  Attaches the telemetry schema to a GitHub release, after its installer:
#  Schema/mac-monitor-telemetry.schema.json as committed at the release's tag,
#  never the working tree's, as Mac-Monitor.telemetry.schema.json.
#
#  Mac-Monitor.pkg must stay the release's first asset: Mac Monitor's update
#  check installs the first asset of the latest release. GitHub lists a
#  release's assets by name, ignoring case, not in upload order, and the
#  schema's name on the release sorts after the pkg's (the repository's
#  mac-monitor-telemetry.schema.json would sort before it). The script refuses
#  to run until the pkg is the first asset, refuses a name that would sort
#  before it, and checks the order again after uploading. Run it on the draft,
#  before publishing (see RELEASING.md).
#
#  The schema's telemetry version must be listed with the file's SHA-256 in
#  Schema/released-versions.txt at the tag, so a released schema can't change
#  without a new version. Attaching the same schema again does nothing, and
#  another schema already attached is refused, never replaced: gh deletes an
#  asset before uploading its replacement, so a failed upload would leave the
#  release without one.
#
#  Author: Brandon Dalton
#
#  Usage: attach-telemetry-schema.sh <tag>
#  Requires: gh, signed in with write access to the repository
#

set -euo pipefail

REPO="Brandon7CC/mac-monitor"
PKG="Mac-Monitor.pkg"
SCHEMA="mac-monitor-telemetry.schema.json"
# The schema's name on the release, TelemetrySchema.releaseAssetName: it sorts after the pkg's.
ASSET="Mac-Monitor.telemetry.schema.json"
TAG="${1:?usage: attach-telemetry-schema.sh <tag>}"
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

fail() { echo "$1" >&2; exit 1; }

# The release's assets in the order of the REST API Mac Monitor's update check reads (it installs assets[0]): a line
# each, the asset's name, a tab, and its digest (sha256:<hex>, or null).
assets() { gh api "repos/$REPO/releases/$RELEASE_ID" --jq '.assets[] | "\(.name)\t\(.digest)"'; }

/usr/bin/git -C "$REPO_DIR" rev-parse --quiet --verify "refs/tags/$TAG" > /dev/null \
    || fail "There's no tag $TAG in $REPO_DIR: fetch it first (git fetch --tags)."

WORK="$(/usr/bin/mktemp -d)"
trap '/bin/rm -rf "$WORK"' EXIT

/usr/bin/git -C "$REPO_DIR" show "$TAG:Schema/$SCHEMA" > "$WORK/$ASSET"
/usr/bin/git -C "$REPO_DIR" show "$TAG:Schema/released-versions.txt" > "$WORK/released-versions.txt"

# The schema's telemetry version: its telemetry_version constant, read with JavaScript for Automation's JSON parser.
VERSION="$(/usr/bin/osascript -l JavaScript - "$WORK/$ASSET" <<'JXA'
function run(argv) {
    const text = $.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, null).js
    return JSON.parse(text).properties.telemetry_version.const
}
JXA
)"
SUM="$(/usr/bin/shasum -a 256 "$WORK/$ASSET" | /usr/bin/cut -d ' ' -f 1)"

/usr/bin/grep -qxF "$VERSION $SUM" "$WORK/released-versions.txt" \
    || fail "Schema/released-versions.txt at $TAG must list the schema's version and SHA-256: $VERSION $SUM"

# `gh release view` finds a draft by its tag too.
RELEASE_ID="$(gh release view "$TAG" --repo "$REPO" --json databaseId --jq .databaseId)"

listing=("${(@f)$(assets)}")
names=("${listing[@]%%$'\t'*}")
[[ "${names[1]}" == "$PKG" ]] \
    || fail "Upload $PKG to $TAG first: it must be the release's first asset. Assets now: ${names[*]:-none}"

# A schema attached before: the same one is left as it is, and another is never replaced.
attached=""
for line in "${listing[@]}"; do
    if [[ "${line%%$'\t'*}" == "$ASSET" ]]; then attached="${line#*$'\t'}"; fi
done
if [[ -n "$attached" ]]; then
    [[ "$attached" == "sha256:$SUM" ]] \
        || fail "Another $ASSET is attached to $TAG: delete it on the release page, then run this again."
    echo "Telemetry $VERSION ($SUM) is already attached to $TAG. Assets: ${names[*]}"
    exit 0
fi

# GitHub will list the assets by name, ignoring case: the pkg must still come first with the schema beside it.
first="$(print -rl -- "${names[@]}" "$ASSET" | LC_ALL=C /usr/bin/sort -f | /usr/bin/head -1)"
[[ "$first" == "$PKG" ]] \
    || fail "GitHub would list $ASSET before $PKG, which must stay the release's first asset: rename the asset."

gh release upload "$TAG" "$WORK/$ASSET" --repo "$REPO"

listing=("${(@f)$(assets)}")
names=("${listing[@]%%$'\t'*}")
[[ "${names[1]}" == "$PKG" && ${names[(Ie)$ASSET]} -gt 0 ]] \
    || fail "Check $TAG's assets: $PKG must be first, beside $ASSET. Assets now: ${names[*]:-none}"

echo "Attached telemetry $VERSION ($SUM) to $TAG as $ASSET. Assets: ${names[*]}"
