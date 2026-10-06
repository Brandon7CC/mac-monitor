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
  SutroESFramework -destination 'platform=macOS'`.
- **arm64e.** Check that notarization accepts the arm64e slices of the app, the Security Extension, the framework and
  `macmonitor`, and, if a Mac or VM on macOS 13 to 15 is at hand, launch the build there once.

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
