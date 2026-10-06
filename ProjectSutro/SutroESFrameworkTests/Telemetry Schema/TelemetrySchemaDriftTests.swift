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
    /// this Mac, under the SDK's names and numbers.
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
    }
    
    /// Every full variant has every field filled: the synthetic decoder missed nothing, new fields included.
    ///
    /// - Throws: The error making up a record.
    func testSyntheticVariantsAreComplete() throws {
        for record in try SyntheticCorpus.records() where record.variant.full {
            let gaps = SyntheticCorpus.gaps(in: record.message, absent: record.variant.absent)
            XCTAssertEqual(gaps, [], record.label)
        }
    }
    
    /// An enum with associated values that no variant names a case for can't be made up, and the failure says where to
    /// name one.
    func testEnumWithoutArmSaysWhereToNameIt() {
        /// An enum the corpus names no case for.
        enum Unnamed: Decodable {
            case path(String), count(Int)
        }
        
        XCTAssertThrowsError(try SyntheticDecoder(SyntheticVariant(name: "full", full: true)).make(Unnamed.self)) {
            let description = SyntheticCorpusError(label: "unnamed (full)", underlying: $0).description
            XCTAssertTrue(description.hasSuffix("name the case it decodes as in the arms of "
                                                + "SyntheticCorpus.variants(of:)."), description)
        }
    }
    
    /// Every synthetic record, of every event type and variant, follows the schema.
    ///
    /// - Throws: The error making up a record or compiling the schema.
    func testSyntheticExportsMatchSchema() throws {
        let exports = try syntheticExports()
        XCTAssertGreaterThan(exports.count, TelemetrySchemaSource.events.count * 2)
        assertValid(exports, with: try generatedValidator())
    }
    
    /// The synthetic records exercise every part of the schema: every key, every type a key allows, every alternative,
    /// every array's elements, and every optional key left out, unless a test machine can't leave it out.
    ///
    /// - Throws: The error making up a record or compiling the schema.
    func testSchemaIsExercised() throws {
        let coverage = CoverageRecorder()
        assertValid(try syntheticExports(), with: try generatedValidator(), coverage: coverage)
        /// eslogger writes `null` where Mac Monitor writes NULL: its record of an override of a file too large to hash.
        let override = try esloggerRecord("gatekeeper_user_override",
                                          type: Int(ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE.rawValue),
                                          ["file_type": 0, "file": "/Applications/Large.app", "sha256": NSNull(),
                                           "signing_info": NSNull()])
        assertValid([("eslogger gatekeeper_user_override", try jsonText(override))],
                     with: try generatedValidator(mode: .eslogger), coverage: coverage)
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
    
    /// eslogger's records and Mac Monitor 2.1's exports, opened as File > Open Trace… opens them (launched-by parents
    /// named) and exported, follow the schema.
    ///
    /// - Throws: The error reading a fixture or compiling the schema.
    func testImportedFixturesMatchSchema() throws {
        let exports = try fixtureExports()
        XCTAssertGreaterThan(exports.count, 20)
        assertValid(exports, with: try generatedValidator())
    }
    
    /// Events captured from Endpoint Security's structs, as the Security Extension captures them, follow the schema:
    /// Open Directory events, remote thread creation, and forks whose launched-by parents the serializer stamps.
    ///
    /// - Throws: The error reading a fixture, serializing a fork, or compiling the schema.
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
        XCTAssertGreaterThan(exports.count, 10)
        assertValid(exports, with: try generatedValidator())
    }
    
    /// "Export all" of a store holding the synthetic records writes JSONL and pretty files that follow the schema.
    ///
    /// - Throws: The error making up records, building the store, exporting it, or validating the files.
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
}
