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
Benchmarks sit beside the tests of the code they time too, named `*PerformanceTests` (see [Performance](#performance)).

| Folder | What's there |
|---|---|
| `TestSupport` | Fakes and helpers the tests share (below) |
| `Fixtures` | Real eslogger and Mac Monitor 2.1 records, `macmonitor stream`'s records of dscl checking a password on macOS 27 and of fseventsd and Spotlight writing their logs and caches, Mac Monitor 3.0's records of adhoc, Developer ID and Apple programs' signing on a Mac with SIP on, and `spctl --raw` output recorded for a notarized and an unsigned package, copied to the test bundle as a folder |
| `Telemetry Schema` | The schema's source (`Source`), the synthetic events it's checked on (`Synthetic`), and its tests |
| `Default Indicators` | The source of the indicators Mac Monitor ships (`Source`): each default, the predicates they're built from and the parts those share, with what each is for. It generates `SutroESFramework/Detection/DefaultIndicators.json`, which the linker copies into the framework's binary. `DefaultIndicatorFileTests` fails when the file and the source differ; `ProjectSutro/Scripts/generate-default-indicators.sh` writes the file again |
| `Scripts` | Tests of `ProjectSutro/Scripts`, run from the source checkout: `compare-performance.js`'s gate |

The folder is synchronized with the test target, so a new file anywhere here builds with the tests without editing the
project, and each folder is a group in Xcode. This README is the one file left out of the target.

The test target depends on the `macmonitor` target, so Xcode builds the tool beside the tests, and
`Command Line/CommandLineBinaryTests` and `Command Line/CommandLineSignalTests` run it: exit statuses, `--version`, a
closed pipe, and how `validate` ends on a first and a second signal. The SutroESFramework test plan sets
`SUTRO_REQUIRE_TOOL=1`, so a missing tool fails them instead of skipping them. Two depend on the Mac and are skipped
otherwise: `testStreamWithoutRootExits77` runs when `SUTRO_STREAM_REFUSED` is `1` (`TEST_RUNNER_SUTRO_STREAM_REFUSED`
through `xcodebuild`), saying this Mac's Security Extension refuses this user's `stream`, and
`testASetUserIDCopyExits77` runs only as root, which alone can make a set-user-ID copy owned by another user.

Two tests read events from outside the checkout: `Detection/Fields/MessageValuesParityTests` checks the Security Extension's
indicator values, and `Detection/Set/CompiledIndicatorsParityTests` its verdicts, against the records of every event the
macath harnesses recorded (`*.events.jsonl`, `macathEvents()`). They find them in
`research/macOS/mac-atomic-test-harnesses/runs` in a folder holding the checkout, or in the folder
`SUTRO_MACATH_RUNS` names (`TEST_RUNNER_SUTRO_MACATH_RUNS` through `xcodebuild`), and are skipped without them.

The Security Extension's string matching is pinned to `NSPredicate` by differential tests
(`Detection/Matching/StringMatchingTests`) and by fuzzing (`Detection/Compiler/IndicatorFuzzTests`), which compiles random predicates and
checks each that compiles against `NSPredicate` on every corpus event's record. Their seeds are fixed
(`SeededGenerator`), so a failure repeats. `Detection/Set/IndicatorIndexTests` checks that the index a set picks each
event's rules by never leaves out one the event matches: on every corpus and macath event against the shipped rules,
copies of them and 2,048 path rules, and on random rules from the same grammar, whose hits must be the rules'
evaluated one by one.

## Test support

Look here before writing a helper of your own, and move one here once a second test file needs it.

### Fakes

| File | What it stands in for |
|---|---|
| `FakeEndpointSecurityClient.swift` | `es_new_client`: records each call, refuses calls on request, holds `es_sync_client` until released, and `deliver(_:)` hands a message to the session's handler. `FakeEndpointSecurityClientFactory.client(.process)` finds a session's client by class |
| `FakeBatchDelivery.swift` | The reader of an `EventBatcher`: keeps each batch and replies only when told (`FakeBatchDelivery`), and an in-memory backlog (`FakeBacklog`) |
| `FakeLaunchServicesReaders.swift` | Launch Services: scripted records (`FakeLaunchServicesReader`), or reads that wait until `open()` (`WaitingLaunchServicesReader`) |
| `FakePeer.swift` | An XPC connection from one effective user and process, which records the code signing requirement pinned on it |
| `StreamHarness.swift` | The Security Extension's side of `macmonitor`: the real `StreamService` on an in-process listener, capturing on fake clients |
| `SensorServiceHarness.swift` | The Security Extension's side of Mac Monitor: the real `SensorService` on an in-process listener, capturing on fake clients with Endpoint Security refusals on request, counting releases and Sensor IDs, with a `FakeUpdater` and a `RecordingAgent` that keeps events and update progress. `NSXPCConnection.sensor` sends any `SensorProtocol` request and waits for the reply |
| `StreamCommandHarness.swift` | `macmonitor stream` in a test: `StreamCommandRun` with output kept in `BufferOutput` |
| `ToolLinkFixture.swift` | A pretend `/` in a temporary directory, for linking `/usr/local/bin/macmonitor` |
| `EndpointSecurityMuteModel.swift` | What `ESClient.h` says a client's mutes are, to check mute diffs against |
| `XCTestCase+MuteStore.swift` | Mute stores in temporary directories, the saved file's bytes, a test console user, and `SavedMuteSet.send(_:access:)`, which sends a request, waits for the reply, and fails the test if none comes |
| `XCTestCase+IndicatorSet.swift` | Indicator sets in temporary directories, the saved file and what it holds, and `SavedIndicatorSet.send(_:access:)`, which sends a request, waits for the reply, and fails the test if none comes |
| `ServiceBeforeIndicators.swift` | A Security Extension older than 3.1 on an in-process listener: it exports the stream interface without `indicators`, so NSXPC cuts the connection off at an indicator request, and counts the stream requests it gets |
| `FakeSensorService.swift` | Mac Monitor's Security Extension on an in-process listener, as 3.0.0 (`SensorProtocolBeforeIndicators`, from `ServiceBeforeIndicators.swift`) or this build exports it, keeping the stream ownership of `SensorService` (pinned by `ESM/Streaming/SensorServiceOwnershipTests`) and noting when the owner's connection closes. `SilentAgent` is Mac Monitor's side, taking every batch |
| `ServiceHoldingChanges.swift` | A 3.1 Security Extension on an in-process listener that lists its indicator set at once but records each change without answering it, as one slow to compile and save a large import seems when `macmonitor`'s wait runs out, or answers each change with one status, such as `unsupported` from one that doesn't know it |
| `XCTestCase+IndicatorCommand.swift` | `macmonitor indicators` end to end against a `StreamHarness` (`runIndicators`, whose `IndicatorRun` keeps its result, output and standard error), and indicator files to import (`indicatorFile(of:named:)`) |
| `XCTestCase+IndicatorEngine.swift` | Mac Monitor's side of the indicator set: user defaults of a test's own (`makeDefaults`), a transport to a `SavedIndicatorSet` as a caller with some access, replying on the main queue (`transport(to:access:)`), and a request sent through an `IndicatorEngine` and waited for (`send(_:through:)`) |
| `Recorded.swift` | Values a test collects from any thread, such as what a fake was asked or what a session emitted, kept in order (`all`). `EmittedEvents` and `DiagnosticLines` are its aliases |

### Raw Messages

| File | What it builds |
|---|---|
| `RawMessageFixture.swift` | An `es_message_t` in memory, freed when the test ends: `rawMessage(version:type:)`, then `file(_:)`, `process(...)`, `token(_:)` |
| `RawMessageFixture+ESLogger.swift` | The same from an eslogger record, so capture tests run on real shapes: `capture(eslogger:fill:)` |
| `RawMessageFixture+Lineage.swift` | Execs and forks with parents, responsible processes and launchd jobs (`esloggerExec`, `esloggerExecEvent`), the launched-by parents tests expect (`LaunchedByParent.appJob`, `.shell`), and a `path` that fails the test if it's read (`noPaths`) |
| `RawMessageFixture+FileEvents.swift` | Opens, closes, creates and mmaps of real paths, for the capture benchmarks |
| `RawMessageFixture+RemoteThreadCreate.swift` | `remote_thread_create` with a thread state |
| `XCTestCase+Capture.swift` | A capture session on fake clients (`makeSession`), messages with sequence numbers (`sequencedMessage`), a serializer a test controls (`StubSerializer`), collected output (`EmittedEvents`), `waitUntil` for a condition another thread makes true, and `awaitCallback`, which starts something that calls back and waits for its first value |

### Export and JSON

| File | What it's for |
|---|---|
| `XCTestCase+Export.swift` | Store an event and export it (`exportText`, `export`), read a record back (`importRecord`), and build eslogger and Mac Monitor 2.1 records by event type (`esloggerRecord`, `legacyRecord`, under the key `esloggerKey` gives) |
| `XCTestCase+Store.swift` | An in-memory event store filled the way the app fills it (`withEventStore`), a SQLite one in a temporary folder or at `/dev/null` (`makeExportStore`), the text exporting it writes (`expectedExport`), and an export that waits until it's done, with its own timeout and, if given, its own choice of events (`run`, or `exportAll` for "Export all") |
| `XCTestCase+Trace.swift` | Numbered eslogger exit events as trace lines (`esloggerExitLine`) or a whole trace (`esloggerTrace`), opening one and waiting for its summary (`openTrace`), and the `mach_time` of each stored event in the order they arrived (`storedMachTimes`) |
| `XCTestCase+Wire.swift` | Every fixture as the `Message`s the app receives, and a message's wire JSON |
| `XCTestCase+JSON.swift` | Parse a JSON object (`jsonObject`, or `jsonObject(encoding:)` for a value), compare JSON by value and key path (`differences`, both ways with `exact: true`, and `assertContains`), and the streaming encoder against `JSONEncoder` (`assertSameJSON`) |
| `JSONPath.swift` | Read or change the value at a path through objects and arrays in one step: `record[path: "event", "exec", "args", 0] = 7`, and `nil` removes the key |
| `JSONCanonicalForm.swift` | JSON with every object's members sorted, for byte-for-byte comparisons |
| `XCTestCase+Fixtures.swift` | Files in `Fixtures/` (`fixture`, `fixtureObject`, `fixtureRecords`) and scratch files and directories that clean up after the test |
| `XCTestCase+Macath.swift` | The macath harnesses' recordings, as files (`macathRecordings`) or as each one's events (`macathEvents`), skipped without them |

### Telemetry Schema

| File | What it's for |
|---|---|
| `XCTestCase+TelemetrySchema.swift` | A validator for the generated schema, every synthetic and fixture export to validate (`fixtureExports`, which pins each fixture's event count and puts each 2.1 Open Directory event in a 2.1 export), and the repository's root for the committed schema |
| `SchemaKeyPaths.swift` | The schema's keys at the paths `Fixtures/eslogger-keys.json` uses |
| `SchemaParts.swift` | Every part of a schema document, for checks that walk all of it |

### Bundles

| File | What it's for |
|---|---|
| `XCTestCase+Bundles.swift` | Unsigned app and shallow bundles in a temporary folder (`makeBundle`), with an XML or binary Info.plist, quarantine and where-froms attributes (`quarantine`, `setWhereFroms`), and the `es_btm_launch_item_t` and `file://` URLs Background Task Management gives (`rawLaunchItem`, `fileURL`) |

### Files

| File | What it's for |
|---|---|
| `FileTypeSamples.swift` | The first bytes of each kind of file a file type check tells apart, made up byte by byte (`machO`, `universal`, `diskImageTrailer`, `tarHeader`), files and copies in a temporary folder whose path has no symbolic link, as Endpoint Security's paths don't (`resolvedTemporaryDirectory`, `temporaryFile(bytes:named:mode:)`, `temporaryCopy(of:named:)`), a file's `stat` as Endpoint Security gives it (`fileStat`), and this process's `FileReader` (`currentReader`) |

### Detection

| File | What it's for |
|---|---|
| `XCTestCase+Indicators.swift` | The shipped indicators compiled once (`shippedIndicators`), one's identity by name (`shippedID`), an indicator of someone's own (`ownIndicator`), what Mac Monitor's own matching finds on an event as it stores it (`matcherHits`), and a check that verdicts are the Security Extension's, each with its indicator's name, severity and `shipped` (`assertStamped`) |
| `CanonicalSpellings.swift` | One path spelled in NFC and in NFD, which Swift's `String` takes as equal and `==`, `!=` and `IN` don't, and pairs of indicators comparing an exec's target path with each (`pairs`), for the program and verdict caches keyed by a predicate's bytes |
| `XCTestCase+ScanBudget.swift` | The scan budget's tests: the synthetic corpus's first exec, changed (`corpusExec`), a predicate on execs compiled (`execProgram`) or as an indicator of someone's own (`execIndicator`), and one program's verdict on a fresh cache with an allowance (`verdict(_:on:limit:)`) |

### Indicator Alerts

| File | What it's for |
|---|---|
| `XCTestCase+IndicatorAlerts.swift` | Notification tests' events: a hit as the Security Extension stamps it (`alertHit`), the corpus's first exec with verdicts (`alertMessage`), a candidate for an indicator (`alertEvent`), and the simulation's scenarios run through a coalescer at each next match or deadline (`ScenarioMatch`, `ScenarioRun`), whose posts `Fixtures/indicator-alert-scenarios.json` holds as the simulation printed them |

### Command Line

| File | What it's for |
|---|---|
| `BuiltTool.swift` | The `macmonitor` beside the test bundle (`BuiltTool.current()`, which fails instead of skipping when `SUTRO_REQUIRE_TOOL` is `1`), run to completion with standard output and error read as it writes them and a 10 s deadline (`run`), or started (`launchTool`, killed when the test ends) to send signals once its trap is set (`waitForSignalTrap`) and finished later (`finish`) |

### XPC

| File | What it's for |
|---|---|
| `XCTestCase+RequestSize.swift` | A request padded with spaces to an exact size (`padded(to:)`), and `assertSizeLimit`, which requires requests at their type's limit to read and one byte more to be refused as too large |

### Errors

| File | What it's for |
|---|---|
| `Thrown.swift` | The error a call throws, to compare with the one expected (`thrown(_:by:)`, `nil` when it returns), and a `Result`'s error (`failure`) |

### Performance

| File | What it's for |
|---|---|
| `PerformanceTestCase.swift` | The benchmarks' base class: skipped unless `SUTRO_PERFORMANCE=1`, and `benchmark(_:unit:operations:setUp:_:)`, one per test, which runs XCTest's `measure` and records each sample. `BenchmarkFailure` fails one that didn't do its work |
| `PerformanceSample.swift` | One sample's wall time, process CPU time and memory footprint change, and their statistics |
| `PerformanceResult.swift` | A benchmark's samples and statistics, per operation |
| `PerformanceReport.swift` | The run's results file, rewritten after each benchmark: JSON, and a CSV beside it |
| `PerformanceEnvironment.swift` | What a run measured on: `hw.model`, the chip and its cores, macOS and its build, Mac Monitor's version, commit and build configuration |
| `PerformanceRun.swift` | The `SUTRO_PERFORMANCE_*` environment variables a run reads |
| `CaptureBenchmarkEvent.swift` | The raw messages the capture benchmarks serialize, and an exec to encode |
| `PerformanceCorpus.swift` | A recording's events (exec, fork, exit, open, close, create, mmap) from 3,000 processes, and its trace |
| `IndicatorBenchmarkEvents.swift` | The indicator benchmarks' events, with native strings as a capture lane builds them (`nativeCopy`), many distinct rules from the shipped ones (`distinctRules`), and path rules (`pathRules`) |
| `IndicatorAdversarialEvents.swift` | The hostile execs the indicator benchmarks and the scan budget's tests evaluate, each within `ARG_MAX` as `execve` counts it (`AdversarialEvent`), with the rules and expectations each is run with, and benign events whose target is a non-ASCII home path (`nonASCIIPathEvent`) |
| `AllocationCounter.swift` | The heap allocations one thread makes while a body runs, through libmalloc's `malloc_logger` hook |

## Performance

The benchmarks time what an event costs on its way through Mac Monitor, so a release, or a Mac, can be compared with
another. A capture lane serializes each event on its Endpoint Security client's queue, so its cost there is what turns
into drops.

| Benchmarks | What they time |
|---|---|
| `capture.serialize.*` | `MessageSerializer.serializeEvent` per event: build, launched-by parent and encode |
| `capture.serialize.*.indicators.*` | The same on a lane that stamps indicators: an empty set, the shipped ones, and 500 of the event's type, each printing its candidates and hits per event. Compare with `capture.serialize.<event>` from the same run |
| `capture.build.*`, `capture.encode.*` | The build (`Message(from:)`, with its enrichment) and the encode (`StreamingJSONEncoder`, and `JSONEncoder` for scale) apart |
| `store.insert` | `insertSystemEvents(messages:)` per event, in the Security Extension's batches of 500 |
| `import.trace`, `export.jsonl` | File > Open Trace... and "Export all", per event |
| `filter.*` | `macmonitor stream`'s filters, and its pipeline with a `--predicate`, per event |
| `enrich.*` | File Quarantine, script and header reads, file types (a read, a hit in a lane's memory, a read's I/O policies, and naming bytes already read: data, a raw disk, text, a property list and a trailer), code signing certificates, and launched-by parent paths |
| `indicators.evaluate.*` | The Security Extension's indicators on one event (`CompiledIndicators`): no rules, the shipped ones, 500 of the event's type, 2,048 path rules, closes Archive written's index looks up, and hostile execs, each printing its rules of the event's type, the rules its index has an event evaluated against, and its allocations per event. Each also prints the scan units an event spends (`ScanBudget`), the pools it was refused and the indicators it left undetermined |
| `alerts.*` | Indicator notifications on Mac Monitor's side: a batch's candidates picked with and without hits, the coalescer per candidate, and a notice's text |
| `indicators.compile.*`, `.footprint.*`, `.concurrent.*`, `.oracle.*` | A set compiled, one rule added to it, the heap it holds, eight lanes sharing one set against each having its own, and Mac Monitor's own matcher on the same events, for the speedup |
| `IndicatorWeightTests` | Not a timed benchmark but a calibration sweep: every Foundation comparison, with no options, `[c]`, `[d]` and `[cd]`, on hostile text of 1 to 64 KiB, fails when a scan unit (`ScanCost`) takes more than 3 ns, and prints each comparison's slowest unit |

Exec has no `capture.serialize` or `capture.build` benchmark: `ProcessExecEvent` retains its message with
`es_retain_message`, which takes only a message Endpoint Security allocated. Its encode is timed from an eslogger record.

The scheme builds the tests with code coverage, and so does the script, so every block of Mac Monitor's code counts
itself in a shared counter. That costs one thread little, but threads running the same code share those counters' cache
lines, so a benchmark of several threads reads slower than a release build would run. `indicators.concurrent.8` is
gated against `indicators.concurrent.8.copies`, whose lanes run the same code on the same build, so the ratio holds with
coverage on. For a manual run without coverage, add `-enableCodeCoverage NO` to the `xcodebuild` command in a copy of
the script, and compare its results only with another run made the same way.

Run them from the command line, which builds them with `-O` and whole-module optimization, as Release ships:

```bash
ProjectSutro/Scripts/test-performance.sh
```

Name classes or tests to run only those (`test-performance.sh MessageSerializerPerformanceTests`), `-s` for the samples
per benchmark (10), and `-o` for the results file. By default it's `ProjectSutro/build/Performance/<time>-<model>-<version>.json`,
with a CSV beside it. In Xcode, pick the Performance test plan (Product > Test Plan) and run the benchmarks from the Test
navigator: Xcode shows XCTest's clock, CPU and memory metrics for each, and the results file is written as well. Xcode
builds the benchmarks' own bundle unoptimized, though (only Mac Monitor's code is optimized in the Community
configuration), and the file says so.

Each results file holds the Mac (`hw.model`, chip, performance and efficiency cores, memory), macOS and its build, its
thermal state and Low Power Mode when the run started, and Mac Monitor's version, commit and build configuration. Then
each benchmark's samples, with the median, minimum, mean and standard deviation per operation, in nanoseconds of wall and
CPU time. Compare two of them, two commits on one Mac or one commit on two Macs:

```bash
ProjectSutro/Scripts/compare-performance.js before.json after.json
```

It lists each benchmark's median time per operation in both, and the change. A change is called "faster" or "slower" only
when it's beyond both runs' noise (twice the larger relative standard deviation, and at least 3%), and otherwise `~`.
`--cpu` compares CPU time instead. It warns when a file's run started throttled, and refuses a file whose build wasn't
optimized (`"optimized": false`, as Xcode's runs write): it exits non-zero, naming the file. `--unoptimized` lists such
files' times and changes anyway, with no verdict. The CSVs of several Macs have the machine on every row, so they can be
pasted into one sheet.

To add a benchmark, subclass `PerformanceTestCase` beside the code's tests, and call `benchmark` once in each test with a
name that stays the same across releases: files are compared by it.

