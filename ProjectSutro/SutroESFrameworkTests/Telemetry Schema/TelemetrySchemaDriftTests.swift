//
//  TelemetrySchemaDriftTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Exports against the schema
/// Fails when Mac Monitor's exports drift from the telemetry schema: every event type's synthetic records (every field
/// filled, and every optional field left out) and the fixtures must follow it, and every part of the schema must be
/// exercised, so a key added to or dropped from an export, or a stale part of the schema, fails here.
final class TelemetrySchemaDriftTests: XCTestCase {
    /// The schema's events are the ones Mac Monitor's export names (``ESEventType``), a superset of those it records on
    /// this Mac, under the SDK's names and numbers, and Mac Monitor's own network events under theirs.
    func testEventListIsComplete() {
        let events = TelemetrySchemaSource.events
        let named = Set(events.map(\.name))
        XCTAssertEqual(named.count, events.count, "An event is described twice")
        let exported = (0..<ES_EVENT_TYPE_LAST.rawValue).map { es_event_type_t(rawValue: $0) }.filter { type in
            let name = eventTypeToString(from: type)
            return name.hasPrefix(SchemaEvent.prefix)
                && ESEventType.CodingKeys(stringValue: name.dropFirst(SchemaEvent.prefix.count).lowercased()) != nil
        }
        XCTAssertEqual(Set(events.map(\.number)), Set(exported.map { Int($0.rawValue) }))
        XCTAssertTrue(Set(supportedEvents.map { Int($0.rawValue) }).isSubset(of: Set(events.map(\.number))))
        for event in events {
            XCTAssertEqual(eventTypeToString(from: es_event_type_t(rawValue: UInt32(event.number))), event.constant)
        }
        let network = TelemetrySchemaSource.networkEvents
        XCTAssertEqual(network.map(\.name), MacMonitorEvent.allCases.map(\.name))
        XCTAssertEqual(network.map(\.number), MacMonitorEvent.allCases.map { Int($0.rawValue) })
        XCTAssertTrue(events.allSatisfy(\.isEndpointSecurity))
        XCTAssertFalse(network.contains(where: \.isEndpointSecurity))
        XCTAssertEqual(TelemetrySchemaSource.allEvents.count, events.count + network.count)
    }
    
    /// Every full variant has every field filled: the synthetic decoder missed nothing, new fields included.
    func testSyntheticVariantsAreComplete() throws {
        for record in try SyntheticCorpus.records() where record.variant.full {
            let gaps = SyntheticCorpus.gaps(in: record.message, absent: record.variant.absent)
            XCTAssertEqual(gaps, [], record.label)
        }
    }
    
    /// Every synthetic record, of every event type and variant, follows the schema.
    func testSyntheticExportsMatchSchema() throws {
        let exports = try syntheticExports()
        XCTAssertGreaterThan(exports.count, TelemetrySchemaSource.events.count * 2)
        assertValid(exports, with: try generatedValidator())
    }
    
    /// The synthetic records exercise every part of the schema: every key, every type a key allows, every alternative,
    /// every array's elements, and every optional key left out, unless a test machine can't leave it out.
    func testSchemaIsExercised() throws {
        let coverage = CoverageRecorder()
        assertValid(try syntheticExports(), with: try generatedValidator(), coverage: coverage)
        /// eslogger writes `null` where Mac Monitor writes NULL: its record of an override of a file too large to hash.
        let override = try esloggerRecord(ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE,
                                          ["file_type": 0, "file": "/Applications/Large.app", "sha256": NSNull(),
                                           "signing_info": NSNull()])
        assertValid([("eslogger gatekeeper_user_override", try jsonText(override))],
                     with: try generatedValidator(mode: .eslogger), coverage: coverage)
        assertValid(try indicatedExports(), with: try generatedValidator(), coverage: coverage)
        assertValid(try lineageExports(), with: try generatedValidator(), coverage: coverage)
        assertValid(try snapshotLines(), with: try generatedValidator(), coverage: coverage)
        let seen = coverage.observations
        let (document, generator) = TelemetrySchemaSource.generate()
        let parts = SchemaParts(document.foundation)
        
        XCTAssertEqual(parts.locations.filter { seen.types[$0] == nil }, [], "Never matched")
        XCTAssertEqual(parts.typeLists.flatMap { location, types in
            types.filter { !(seen.types[location] ?? []).contains($0) }.map { "\(location): \($0.rawValue)" }
        }.sorted(), [], "Types never seen")
        XCTAssertEqual(parts.branches.flatMap { location, count in
            (0..<count).filter { !(seen.branches[location] ?? []).contains($0) }.map { "\(location)/anyOf/\($0)" }
        }.sorted(), [], "Alternatives never matched")
        let unobserved = parts.optionalKeys.filter { object, key in
            let place = generator.keys["\(object)/properties/\(JSONSchemaCompiler.escape(key))"]
            return place?.key.absence?.observable != false && !(seen.absences[object] ?? []).contains(key)
        }
        XCTAssertEqual(unobserved.map { "\($0.object): \($0.key)" }, [], "Optional keys never left out")
    }
    
    /// eslogger's records and Mac Monitor 2.1's exports, opened as File > Open Trace... opens them (launched-by parents
    /// named) and exported, follow the schema.
    func testImportedFixturesMatchSchema() throws {
        let exports = try fixtureExports()
        XCTAssertGreaterThan(exports.count, 20)
        assertValid(exports, with: try generatedValidator())
    }
    
    /// Events captured from Endpoint Security's structs, as the Security Extension captures them, follow the schema:
    /// Open Directory events, remote thread creation, forks whose launched-by parents the serializer stamps, and
    /// network flows a capture session read from the kernel's messages.
    func testCapturedMessagesMatchSchema() throws {
        var exports: [(label: String, json: String)] = []
        for (index, record) in try fixtureRecords("eslogger-od.jsonl").enumerated() {
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
            fixture.fillEnvelope(eslogger: record)
            guard fixture.fillODEvent(eslogger: record) else { continue }
            exports.append(("eslogger-od.jsonl[\(index)] captured", exportText(Message(from: fixture.raw))))
        }
        for (index, record) in try fixtureRecords("eslogger-remote-thread-create.jsonl").enumerated() {
            let message = capture(eslogger: record) { $0.fillRemoteThreadCreate(eslogger: record) }
            exports.append(("eslogger-remote-thread-create.jsonl[\(index)] captured", exportText(message)))
        }
        /// A shell's fork, whose launched-by parent is its Unix parent, and launchd's, whose launched-by parent is the
        /// responsible process, named from a path the serializer reads.
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR", encoder: StreamingJSONEncoder())
        let serializer = MessageSerializer(processPath: { pid, _ in "/read/\(pid)" })
        let forks: [(label: String, parent: (Int32, UInt32), responsible: (Int32, UInt32))] = [
            ("shell", (401, 4010), (400, 4000)), ("launchd", (1, 1), (500, 5000)),
        ]
        for (label, parent, responsible) in forks {
            let fork = rawMessage(type: ES_EVENT_TYPE_NOTIFY_FORK)
            fork.fork(childPID: 402, parent: RawMessageFixture.auditToken(pid: parent.0, pidversion: parent.1),
                      responsible: RawMessageFixture.auditToken(pid: responsible.0, pidversion: responsible.1))
            let json = try XCTUnwrap(serializer.serialize(fork.raw, in: lane))
            let message = try JSONDecoder().decode(Message.self, from: json)
            XCTAssertNotNil(message.createdLaunchedByParent, label)
            exports.append(("\(label) fork serialized", exportText(message)))
        }
        exports += try capturedFlows().map { ("\($0.es_event_type ?? "") captured", exportText($0)) }
        XCTAssertGreaterThan(exports.count, 10)
        assertValid(exports, with: try generatedValidator())
    }
    
    /// Network flows as a capture session records them from the kernel's messages: a live process's, with a URL, and
    /// a reaped process's, whose record has only its pid.
    ///
    /// - Returns: The events, in order.
    /// - Throws: If the session couldn't start, or an event doesn't decode.
    private func capturedFlows() throws -> [Message] {
        let flows = FlowClientHarness(), emitted = EmittedEvents()
        let configuration = CaptureConfiguration(events: MacMonitorEvent.allCases.map(\.type), label: "Test")
        let session = try makeSession(configuration, factory: FakeEndpointSecurityClientFactory(),
                                      flows: flows.client, emitted: emitted)
        session.isRecording = true
        XCTAssertTrue(flows.feed(flows.flow() + flows.flow(pid: 300)))
        session.stop()
        XCTAssertEqual(emitted.all.count, 4)
        return try emitted.all.map { try JSONDecoder().decode(Message.self, from: $0.json) }
    }

    /// "Export all" of a store holding the synthetic records writes JSONL and pretty files that follow the schema.
    func testExporterFilesMatchSchema() throws {
        let messages = try SyntheticCorpus.records().map(\.message)
        let store = try makeExportStore(messages)
        let validator = try generatedValidator()
        for pretty in [false, true] {
            let (url, events) = try exportAll(store, pretty: pretty)
            XCTAssertEqual(events, messages.count)
            let report = try validator.validate(traceAt: url)
            XCTAssertEqual(report.records, messages.count)
            XCTAssertTrue(report.isValid, report.report(fileName: url.lastPathComponent))
        }
    }
    
    /// Synthetic records that list indicators, as Export telemetry and `macmonitor stream` write them. Matched as
    /// they're written (`export`): one Mac Monitor ships, with its tactic and technique, and two of someone's own with
    /// neither, all matching every event, a severity each. Then the Security Extension's verdicts, stored with the
    /// event (`security_extension`), which the record lists instead: hits, and none. The first also lists two the
    /// Security Extension couldn't rule out, one Mac Monitor ships and one of someone's own, a reason each.
    ///
    /// - Returns: A few labeled records.
    /// - Throws: When the corpus can't be read, or the event model is missing.
    private func indicatedExports() throws -> [(label: String, json: String)] {
        var shipped = Indicator.defaults[0]
        shipped.rule = .event("event_type >= 0")
        shipped.severity = .medium
        let own = Indicator(name: "Every event", description: "", symbol: "star", color: .red,
                            predicate: "event_type >= 0", severity: .high)
        var quiet = own
        quiet.id = UUID()
        quiet.severity = .low
        XCTAssertEqual(Set([shipped, own, quiet].map(\.severity)), Set(IndicatorSeverity.allCases))
        let encoder = ExportEncoder(model: try XCTUnwrap(ExportEncoder.model), indicators: [shipped, own, quiet])
        /// Two Endpoint Security events, and a network flow, whose record lists them under its own definition.
        let corpus = try SyntheticCorpus.records()
        let records = Array(corpus.prefix(2)) + [try XCTUnwrap(corpus.first { $0.message.event.isNetworkFlow })]
        let matched = records.map { record in
            ("\(record.label) with indicators", String(decoding: encoder.line(for: record.message), as: UTF8.self))
        }
        /// The first says what it matched, a string, a number and a Boolean, and the others list nothing.
        let fields = [IndicatorMatchedField(field: "event.exec.target.executable.path", value: .string("/bin/sh")),
                      IndicatorMatchedField(field: "process.audit_token.pid", value: .integer(42)),
                      IndicatorMatchedField(field: "process.is_platform_binary", value: .boolean(true))]
        let verdicts = [IndicatorVerdicts([shipped, own, quiet].map {
            var hit = IndicatorHit(Self.revised($0), isDefault: $0.id == shipped.id, pack: 2,
                                   evaluatedBy: .securityExtension)
            if $0.id == shipped.id { hit.matched = fields }
            return hit
        }), IndicatorVerdicts()]
        var undecided = own
        undecided.id = UUID()
        let unsettled = zip([Indicator.defaults[1], undecided], UndeterminedReason.known)
        let undetermined = [UndeterminedIndicators(unsettled.map {
            let isDefault = $0.id == Indicator.defaults[1].id
            return IndicatorUndetermined(IndicatorHit(isDefault ? Self.revised($0) : $0, isDefault: isDefault,
                                                      pack: 2, evaluatedBy: .securityExtension), reason: $1)
        }), nil]
        let stamps = Array(zip(verdicts, undetermined)) + [(verdicts[0], undetermined[0])]
        let stamped = zip(records, stamps).map { record, stamp in
            var message = record.message
            (message.indicators, message.indicators_undetermined) = stamp
            return ("\(record.label) with \(stamp.0.hits.count) stamped indicators",
                    String(decoding: encoder.line(for: message), as: UTF8.self))
        }
        XCTAssertTrue(stamped[0].1.contains(#""evaluated_by":"security_extension""#), stamped[0].0)
        for reason in UndeterminedReason.known {
            XCTAssertTrue(stamped[0].1.contains(#""reason":"\#(reason.rawValue)""#), stamped[0].0)
        }
        XCTAssertTrue(stamped[1].1.contains(#""indicators":[]"#), stamped[1].0)
        XCTAssertTrue(matched[0].1.contains(#""evaluated_by":"export""#), matched[0].0)
        return matched + stamped
    }

    /// An exec and a fork as the Security Extension stamps them while it tracks lineage, with their ancestors' keys,
    /// and as it writes them while it doesn't, with none.
    ///
    /// - Returns: The labeled records.
    /// - Throws: When a fixture can't be read, or the event model is missing.
    private func lineageExports() throws -> [(label: String, json: String)] {
        let lineage = ProcessLineage()
        lineage.seed([(ProcessProgram(key: ProcessKey(pid: 100, pidversion: 1), path: "/bin/zsh"), 1)])
        let shell = try esloggerProcess(pid: 100, pidversion: 1, path: "/bin/zsh", parent: (1, 7))
        let child = try esloggerProcess(pid: 200, pidversion: 2, path: "/bin/zsh", parent: (100, 1))
        let target = try esloggerProcess(pid: 200, pidversion: 3, path: "/usr/bin/true", parent: (100, 1))
        let encoder = ExportEncoder(model: try XCTUnwrap(ExportEncoder.model))
        let events = [("exec", try execMessage(by: child, of: target)), ("fork", try forkMessage(by: shell, of: child))]
        return events.flatMap { name, message -> [(label: String, json: String)] in
            var stamped = message
            stamped.stampAncestorKeys(from: lineage)
            return [("\(name) with ancestor keys", String(decoding: encoder.line(for: stamped), as: UTF8.self)),
                    ("\(name) without lineage", String(decoding: encoder.line(for: message), as: UTF8.self))]
        }
    }

    /// Process snapshots' lines: one with every field and an ancestor, and one of a process known by its key alone,
    /// with none.
    ///
    /// - Returns: The lines, labeled.
    /// - Throws: A failure when a snapshot can't be encoded.
    private func snapshotLines() throws -> [(label: String, json: String)] {
        let full = ProcessProgram(key: ProcessKey(pid: 100, pidversion: 1), path: "/bin/zsh", commandLine: "-zsh",
                                  signingID: "com.apple.zsh", teamID: "TEAM", codesigningType: "PLATFORM")
        let snapshots = [("a process snapshot", ProcessSnapshot(full, ancestors: [ProcessKey(pid: 50, pidversion: 1)])),
                         ("a process snapshot of a key alone",
                          ProcessSnapshot(ProcessProgram(key: ProcessKey(pid: 50, pidversion: 1)), ancestors: []))]
        return try snapshots.enumerated().map { index, entry in
            /// The second says nothing of where it's from, as a test fixture's doesn't.
            let record = ProcessSnapshotRecord(entry.1, sensorID: index == 0 ? "SENSOR" : nil,
                                               bootSession: index == 0 ? SyntheticValues.uuid.uuidString : nil)
            return (entry.0, String(decoding: try XCTUnwrap(record.line), as: UTF8.self))
        }
    }

    /// An indicator as a pack has one, with a revision, so a hit's `revision` is a number.
    ///
    /// - Parameter indicator: The indicator.
    /// - Returns: It, at revision 3.
    private static func revised(_ indicator: Indicator) -> Indicator {
        var revised = indicator
        revised.revision = 3
        return revised
    }
}
