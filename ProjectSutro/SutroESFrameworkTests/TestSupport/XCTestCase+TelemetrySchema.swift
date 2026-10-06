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
    /// The repository's root: three folders up from this file, which is in `ProjectSutro/SutroESFrameworkTests/
    /// TestSupport`. Ties the schema's file tests to a source checkout, as `xcodebuild` runs them.
    static let repositoryURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    
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
    
    /// Every record of eslogger's fixtures and Mac Monitor 2.1's, opened as File > Open Trace… opens them (launched-by
    /// parents named) and exported without a store, as the command line encodes them. Event types Mac Monitor doesn't
    /// record are left out, as Open Trace leaves them out.
    ///
    /// - Returns: Each record's label (`eslogger-od.jsonl[3]`) and export, in the fixtures' order.
    /// - Throws: The error reading a fixture or a record.
    func fixtureExports() throws -> [(label: String, json: String)] {
        var exports: [(label: String, json: String)] = []
        for name in ["eslogger-exit.jsonl", "eslogger-open.jsonl", "eslogger-lineage.jsonl", "eslogger-od.jsonl",
                     "eslogger-remote-thread-create.jsonl", "macmonitor-2.1-exit.jsonl", "macmonitor-2.1-od.json"] {
            var messages: [Message] = []
            let reader = try TraceRecordReader(url: try fixtureURL(name))
            while let record = try reader.next() {
                guard case .object(let json, _) = record else { continue }
                do {
                    messages.append(try TraceImporter.message(from: json))
                } catch TraceImportError.unsupportedEvent, TraceImportError.notAnEvent {
                    /// An event type Mac Monitor doesn't record, or a fixture's comment.
                    continue
                }
            }
            TraceLaunchedByParents().fill(&messages)
            exports += messages.enumerated().map { ("\(name)[\($0)]", exportText($1)) }
        }
        return exports
    }
}
