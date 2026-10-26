# SutroESFramework tests

The tests run the real framework code and fake only what a test process can't have: Endpoint Security, root, code
signing and a slow reader. The suite needs no root, no Endpoint Security and no VM, and runs in about 12 seconds:

```bash
xcodebuild test -project ProjectSutro/ProjectSutro.xcodeproj -scheme SutroESFramework -destination 'platform=macOS'
```

## Layout

The folders mirror `SutroESFramework`'s, so a test sits at the same path as the code it tests: the tests for
`ESM/Capture/Event Classes/EventClassTable.swift` are in `ESM/Capture/Event Classes/EventClassTableTests.swift`, and an
event's own tests are in its folder under `Events/Models`. A test of several files goes with the one it's mostly about.
The launched-by parent's tests are all in `ESM/LaunchedByParent`, though its code spans capture, export and import.

| Folder | What's there |
|---|---|
| `TestSupport` | Fakes and helpers the tests share (below) |
| `Fixtures` | Real eslogger and Mac Monitor 2.1 records, copied to the test bundle as a folder |
| `Telemetry Schema` | The schema's source (`Source`), the synthetic events it's checked on (`Synthetic`), and its tests |

The folder is synchronized with the test target, so a new file anywhere here builds with the tests without editing the
project, and each folder is a group in Xcode. This README is the one file left out of the target.

## Test support

Look here before writing a helper of your own, and move one here once a second test file needs it.

### Fakes

| File | What it stands in for |
|---|---|
| `FakeEndpointSecurityClient.swift` | `es_new_client`: records each call, refuses calls on request, holds `es_sync_client` until released, and `deliver(_:)` hands a message to the session's handler. `FakeEndpointSecurityClientFactory.client(.process)` finds a session's client by class |
| `FakeBatchDelivery.swift` | The reader of an `EventBatcher`: keeps each batch and replies only when told (`FakeBatchDelivery`), and an in-memory backlog (`FakeBacklog`) |
| `FakeLaunchServicesReaders.swift` | Launch Services: scripted records (`FakeLaunchServicesReader`), or reads that wait until `open()` (`WaitingLaunchServicesReader`) |
| `FakePeer.swift` | An XPC connection from one effective user, which records the code signing requirement pinned on it |
| `StreamHarness.swift` | The Security Extension's side of `macmonitor`: the real `StreamService` on an in-process listener, capturing on fake clients |
| `StreamCommandHarness.swift` | `macmonitor stream` in a test: `StreamCommandRun` with output kept in `BufferOutput` |
| `ToolLinkFixture.swift` | A pretend `/` in a temporary directory, for linking `/usr/local/bin/macmonitor` |
| `EndpointSecurityMuteModel.swift` | What `ESClient.h` says a client's mutes are, to check mute diffs against |
| `XCTestCase+MuteStore.swift` | Mute stores in temporary directories, the saved file's bytes, a test console user, and `SavedMuteSet.send(_:access:)`, which sends a request and waits for the reply |
| `Recorded.swift` | Values a test collects from any thread, such as what a fake was asked or what a session emitted, kept in order (`all`). `EmittedEvents` and `DiagnosticLines` are its aliases |

### Raw Messages

| File | What it builds |
|---|---|
| `RawMessageFixture.swift` | An `es_message_t` in memory, freed when the test ends: `rawMessage(version:type:)`, then `file(_:)`, `process(…)`, `token(_:)` |
| `RawMessageFixture+ESLogger.swift` | The same from an eslogger record, so capture tests run on real shapes: `capture(eslogger:fill:)` |
| `RawMessageFixture+Lineage.swift` | Execs and forks with parents, responsible processes and launchd jobs (`esloggerExec`, `esloggerExecEvent`), the launched-by parents tests expect (`LaunchedByParent.appJob`, `.shell`), and a `path` that fails the test if it's read (`noPaths`) |
| `RawMessageFixture+RemoteThreadCreate.swift` | `remote_thread_create` with a thread state |
| `XCTestCase+Capture.swift` | A capture session on fake clients (`makeSession`), messages with sequence numbers (`sequencedMessage`), a serializer a test controls (`StubSerializer`), collected output (`EmittedEvents`), `waitUntil` for a condition another thread makes true, and `awaitCallback`, which starts something that calls back and waits for its first value |

### Export and JSON

| File | What it's for |
|---|---|
| `XCTestCase+Export.swift` | Store an event and export it (`exportText`, `export`), read a record back (`importRecord`), and build eslogger and Mac Monitor 2.1 records by event type (`esloggerRecord`, `legacyRecord`, under the key `esloggerKey` gives) |
| `XCTestCase+Store.swift` | An in-memory event store filled the way the app fills it (`withEventStore`), a SQLite one in a temporary folder or at `/dev/null` (`makeExportStore`), the text exporting it writes (`expectedExport`), and an export that waits until it's done, with its own timeout (`run`, or `exportAll` for "Export all") |
| `XCTestCase+Wire.swift` | Every fixture as the `Message`s the app receives, and a message's wire JSON |
| `XCTestCase+JSON.swift` | Parse a JSON object (`jsonObject`, or `jsonObject(encoding:)` for a value), compare JSON by value and key path (`differences`, `assertContains`), and the streaming encoder against `JSONEncoder` (`assertSameJSON`) |
| `JSONPath.swift` | Read or change the value at a path through objects and arrays in one step: `record[path: "event", "exec", "args", 0] = 7`, and `nil` removes the key |
| `JSONCanonicalForm.swift` | JSON with every object's members sorted, for byte-for-byte comparisons |
| `XCTestCase+Fixtures.swift` | Files in `Fixtures/` (`fixture`, `fixtureObject`, `fixtureRecords`) and scratch files and directories that clean up after the test |

### Telemetry Schema

| File | What it's for |
|---|---|
| `XCTestCase+TelemetrySchema.swift` | A validator for the generated schema, every synthetic and fixture export to validate, and the repository's root for the committed schema |
| `SchemaKeyPaths.swift` | The schema's keys at the paths `Fixtures/eslogger-keys.json` uses |
| `SchemaParts.swift` | Every part of a schema document, for checks that walk all of it |

### Errors

| File | What it's for |
|---|---|
| `Thrown.swift` | The error a call throws, to compare with the one expected (`thrown(_:by:)`, `nil` when it returns), and a `Result`'s error (`failure`) |
