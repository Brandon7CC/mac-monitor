//
//  XCTestCase+TelemetrySchema.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import CryptoKit
@testable import SutroESFramework


// MARK: - The telemetry schema in tests
extension XCTestCase {
    /// The repository's root: the folder holding `ProjectSutro/SutroESFrameworkTests`, which holds this file at any
    /// depth. Ties the schema's file tests to a source checkout, as `xcodebuild` runs them.
    static let repositoryURL: URL = {
        var url = URL(fileURLWithPath: #filePath)
        while url.lastPathComponent != "SutroESFrameworkTests" && url.pathComponents.count > 1 {
            url.deleteLastPathComponent()
        }
        return url.deletingLastPathComponent().deletingLastPathComponent()
    }()
    
    /// The committed schema: `Schema/mac-monitor-telemetry.schema.json`.
    static var schemaFileURL: URL {
        repositoryURL.appendingPathComponent("Schema").appendingPathComponent(TelemetrySchema.fileName)
    }
    
    /// The committed schema's SHA-256, in lowercase hex, as `shasum -a 256` prints it.
    static var schemaSHA256: String {
        get throws {
            SHA256.hash(data: try Data(contentsOf: schemaFileURL)).map { String(format: "%02x", $0) }.joined()
        }
    }
    
    /// A validator for the schema the source generates, which the committed one must equal.
    ///
    /// - Parameter mode: Which keys are checked.
    /// - Returns: The validator.
    /// - Throws: The error compiling the schema.
    func generatedValidator(mode: TelemetryValidator.Mode = .macMonitor) throws -> TelemetryValidator {
        try TelemetryValidator(schema: Data(TelemetrySchemaSource.text.utf8), mode: mode)
    }
    
    /// Assert that exported records follow the schema, naming each one that doesn't and its issues.
    ///
    /// - Parameters:
    ///   - exports: Each record's label (its event and variant, or its fixture) and JSON text.
    ///   - validator: The validator.
    ///   - coverage: Records what the records exercise.
    ///   - file: The caller's file.
    ///   - line: The caller's line.
    func assertValid(_ exports: [(label: String, json: String)], with validator: TelemetryValidator,
                     coverage: CoverageRecorder? = nil, file: StaticString = #filePath, line: UInt = #line) {
        var failures: [String] = []
        for (label, json) in exports {
            guard let record = try? JSONSerialization.jsonObject(with: Data(json.utf8)) else {
                failures.append("\(label): not JSON")
                continue
            }
            let issues = validator.issues(in: record, coverage: coverage)
            guard !issues.isEmpty else { continue }
            failures.append("\(label):\n    " + issues.map(\.description).joined(separator: "\n    "))
        }
        XCTAssertTrue(failures.isEmpty, "\(failures.count) of \(exports.count) records don't follow the schema:\n"
                      + failures.joined(separator: "\n"), file: file, line: line)
    }
    
    /// Every synthetic record, exported without a store as the command line encodes it.
    ///
    /// - Returns: Each record's label and export.
    /// - Throws: The error making up a record.
    func syntheticExports() throws -> [(label: String, json: String)] {
        try SyntheticCorpus.records().map { ($0.label, exportText($0.message)) }
    }
    
    /// How many events each fixture holds, in the order ``fixtureExports(file:line:)`` reads them. Every one is an
    /// event Mac Monitor records.
    static let fixtureEventCounts: KeyValuePairs<String, Int> = [
        "eslogger-exit.jsonl": 1, "eslogger-open.jsonl": 1, "eslogger-lineage.jsonl": 10, "eslogger-od.jsonl": 11,
        "eslogger-remote-thread-create.jsonl": 2, "macmonitor-2.1-exit.jsonl": 1, "macmonitor-2.1-od.json": 6,
    ]
    
    /// Every record of eslogger's fixtures and Mac Monitor 2.1's, opened as File > Open Trace... opens them
    /// (launched-by parents named) and exported without a store, as the command line encodes them. The 2.1 Open
    /// Directory fixture is a map of events, so each is put in a 2.1 export of its own (`legacyRecord`). Every record
    /// must be an event Mac Monitor records, and each fixture must give the count ``fixtureEventCounts`` pins.
    ///
    /// - Parameters:
    ///   - file: The caller's file.
    ///   - line: The caller's line.
    /// - Returns: Each record's label (`eslogger-od.jsonl[3]`, `macmonitor-2.1-od.json[od_create_user]`) and export,
    ///   in the fixtures' order.
    /// - Throws: The error reading a fixture or importing a record.
    func fixtureExports(file: StaticString = #filePath, line: UInt = #line) throws -> [(label: String, json: String)] {
        var exports: [(label: String, json: String)] = []
        for (name, count) in Self.fixtureEventCounts {
            var labelled: [(label: String, message: Message)] = []
            if name.hasSuffix(".jsonl") {
                let reader = try TraceRecordReader(url: try fixtureURL(name))
                while let record = try reader.next() {
                    guard case .object(let json, _) = record else { continue }
                    labelled.append(("\(name)[\(labelled.count)]", try TraceImporter.message(from: json)))
                }
            } else {
                for (key, event) in try legacyEvents(name) {
                    let type = try XCTUnwrap(CommandLineEvents.notifyEvent(named: key), key, file: file, line: line)
                    labelled.append(("\(name)[\(key)]", try importRecord(try legacyRecord(type, event))))
                }
            }
            XCTAssertEqual(labelled.count, count, "Events in \(name)", file: file, line: line)
            var messages = labelled.map(\.message)
            TraceLaunchedByParents().fill(&messages)
            exports += zip(labelled, messages).map { ($0.label, exportText($1)) }
        }
        return exports
    }
    
    /// The events of a Mac Monitor 2.1 fixture that holds them by key, as `macmonitor-2.1-od.json` does.
    ///
    /// - Parameter name: The fixture's file name.
    /// - Returns: Each event's key, such as `od_create_user`, and object, sorted by key.
    /// - Throws: An `XCTest` failure if the fixture has no `events` object.
    private func legacyEvents(_ name: String) throws -> [(key: String, event: Any)] {
        let events = try XCTUnwrap(try fixtureObject(name)["events"] as? [String: Any], "No events in \(name)")
        return events.keys.sorted().map { ($0, events[$0]!) }
    }
}
