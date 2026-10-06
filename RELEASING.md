# Releasing Mac Monitor

Releases are published by hand on GitHub. Nothing builds or uploads a release on its own: `.github/release.yml`
isn't a workflow GitHub runs (it isn't in `.github/workflows`).

Every release has these assets, in this order:

1. `Mac-Monitor.pkg`, the notarized installer. Mac Monitor's update check installs the **first** asset of the latest
   release (`UpdateInstaller` reads `assets[0]` of `releases/latest`), and every Mac Monitor already installed does
   the same, so the pkg must always be first.
2. `Mac-Monitor.telemetry.schema.json`, the telemetry schema of the release's exports (see
   [`Schema/README.md`](Schema/README.md)).

GitHub lists a release's assets by name, ignoring case, not in the order they were uploaded, so the order comes from
the names: the schema's name on a release sorts after the pkg's. The repository's own name for it,
`mac-monitor-telemetry.schema.json`, would sort first (`-` comes before `.`), so never upload that file by hand.

## Before tagging

- **Telemetry schema.** If any export changed since the last release, bump `TelemetrySchema.version`
  (`ProjectSutro/SutroESFramework/Telemetry Schema/TelemetrySchema.swift`): MAJOR when a key is removed, renamed or
  retyped, or a value's format changes; MINOR when a key, an event type, or a value of an enum is added; PATCH when
  only the schema's text changes. Then run `ProjectSutro/Scripts/generate-telemetry-schema.sh` and commit `Schema/`.
  The tests fail while the committed schema isn't what the source generates.
- **Released versions.** Add a line `<version> <SHA-256>` for the schema to `Schema/released-versions.txt`, unless
  it's already there, and commit it. The hash is `shasum -a 256 Schema/mac-monitor-telemetry.schema.json`, and
  `attach-telemetry-schema.sh` prints the exact line when it's missing. From then on, `TelemetrySchemaFileTests` fails
  if that version's schema changes.
- **Tests.** Every test passes: `xcodebuild test -project ProjectSutro/ProjectSutro.xcodeproj -scheme
  SutroESFramework -destination 'platform=macOS'`. On Apple silicon, Xcode's test runner is arm64, so that runs the
  tests with pointer authentication off, and from macOS 14.4 its dyld loads the tests' and the framework's arm64e
  slices. So also run the same command with `ARCHS=arm64` at the end, for the arm64 slices that macOS 13 to 14.3 load,
  and, on macOS 26 or later, `ProjectSutro/Scripts/test-arm64e.sh`, which runs the arm64e slices with pointer
  authentication on.
- **arm64e.** Every Mach-O ships x86_64, arm64 and arm64e (`ENABLE_POINTER_AUTHENTICATION` in the project's three
  configurations). On the notarized build:
  - Slices: `find "Mac Monitor.app" -type f | while read -r f; do a=$(lipo -archs "$f" 2>/dev/null) && echo "$a  $f";
    done` prints `x86_64 arm64 arm64e` for each of the five: `Mac Monitor`, `macmonitor`, the Security Extension and
    both copies of the framework. An arm64e process with pointer authentication on can't load a library without
    arm64e, so anything embedded later needs it too.
  - ABI: `lipo -detailed_info` names the arm64e slice of the three executables `arm64e.v1` (`PTR_AUTH_VERSION
    USERSPACE 1`), as Xcode 27 writes it. macOS 13 to 26.4 prefer an arm64e slice to arm64, and refuse to run an
    executable that isn't Apple's when that slice is ABI 0, so a build whose executables say plain `arm64e` doesn't
    launch on Apple silicon below 26.5.
  - Signing: `codesign --verify --deep --strict --all-architectures "Mac Monitor.app"` passes, and notarization
    accepts the pkg with nothing about arm64e in `xcrun notarytool log <submission-id>`. Apple documents no arm64e
    rule for the notary service, and Gatekeeper finds a ticket by the cdhash of the slice that runs, so an accepted
    pkg isn't enough: its ticket must have an `arm64e` entry, beside `x86_64` and `arm64`, for each of the five.
    `xcrun notarytool log <submission-id> | jq -r '.ticketContents[] | "\(.arch) \(.path)"'` lists them. If
    notarization refuses the slices, or the ticket has no arm64e entries, set `ENABLE_POINTER_AUTHENTICATION = NO`
    in the project's three configurations and ship x86_64 and arm64 as 2.1 did.
  - Launch: install the pkg, allow the Security Extension, start a capture and run `sudo macmonitor stream` on Apple
    silicon on macOS 26 or later, which runs arm64e with pointer authentication on, and on Intel. If Macs or VMs on
    macOS 13 to 15 are at hand, do it there too, on one from 13.0 to 14.3 and one from 14.4 to 15: both run the
    executables' arm64e slices with pointer authentication off, but 13 to 14.3 (dyld 1125.5 and earlier) load the
    framework's arm64 slice into them, and 14.4 and later its arm64e slice (as xnu's and dyld's sources read; not yet
    tried there). `sudo vmmap --summary <pid> | grep "Code Type"` shows which slice a process runs.

## Publishing

1. Tag the release commit and push the tag.
2. Create the GitHub release as a **draft** for the tag, with `Mac-Monitor.pkg`:
   `gh release create <tag> --draft Mac-Monitor.pkg`, or the release page.
3. Attach the schema: `ProjectSutro/Scripts/attach-telemetry-schema.sh <tag>`. It uploads the tag's
   `Schema/mac-monitor-telemetry.schema.json` as `Mac-Monitor.telemetry.schema.json`, and refuses to run unless the
   pkg is already the first asset, the schema's name sorts after it, and `Schema/released-versions.txt` at the tag
   lists the schema's version and SHA-256.
4. Publish the draft.
5. Check that the pkg is still first: `gh api repos/Brandon7CC/mac-monitor/releases/latest --jq '.assets[0].name'`
   must print `Mac-Monitor.pkg`.

## Replacing an asset

Only possible while GitHub allows changing the release's assets (never on a published immutable release).

- **The schema**: a released version's schema never changes, so running `attach-telemetry-schema.sh <tag>` again
  does nothing when the same file is attached, and refuses another one rather than replace it (`gh release upload
  --clobber` deletes the attached asset first, and a failed upload would leave the release without it). To attach
  another schema to a draft, delete the attached one on the release page, then run the script again.
- **The pkg**: only on a draft. While no pkg is attached, the schema is the release's first asset, so replace the
  pkg (delete it and upload the new one, or `gh release upload <tag> Mac-Monitor.pkg --clobber`) before
  publishing, and check the order again.
