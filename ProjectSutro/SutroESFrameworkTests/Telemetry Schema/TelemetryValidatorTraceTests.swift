//
//  TelemetryValidatorTraceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Validating traces
/// Pins how ``TelemetryValidator`` streams a trace: every shape the importer reads, line numbers, malformed records,
/// the issue limit, cancellation, progress, hints, and parallel batches that keep file order.
final class TelemetryValidatorTraceTests: XCTestCase {
    /// A schema of small records: a telemetry version, an event name, and eslogger's `n`, with eslogger's envelope
    /// and a list of integers, which they may leave out.
    private let schema = """
        {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
         "properties": {"telemetry_version": {"type": "string", "const": "1.0.0",
                                              "x-mac-monitor-origin": "mac-monitor"},
                        "es_event_type": {"type": "string", "x-mac-monitor-origin": "mac-monitor"},
                        "n": {"type": "integer", "x-mac-monitor-origin": "eslogger"},
                        "schema_version": {"type": "integer", "x-mac-monitor-origin": "eslogger"},
                        "event_type": {"type": "integer", "x-mac-monitor-origin": "eslogger"},
                        "event": {"type": "object", "x-mac-monitor-origin": "eslogger"},
                        "list": {"type": "array", "items": {"type": "integer"}, "x-mac-monitor-origin": "eslogger"}},
         "required": ["telemetry_version", "es_event_type", "n"], "additionalProperties": false}
        """
    
    /// The validator of ``schema``.
    private var validator: TelemetryValidator { get throws { try TelemetryValidator(schema: Data(schema.utf8)) } }
    
    /// A record.
    ///
    /// - Parameters:
    ///   - n: Its `n`: a valid record has a number, an invalid one a string.
    ///   - version: Its telemetry version.
    /// - Returns: The record's object.
    private func record(_ n: Any, version: String = "1.0.0") -> [String: Any] {
        ["telemetry_version": version, "es_event_type": "ES_EVENT_TYPE_NOTIFY_EXIT", "n": n]
    }
    
    /// A record of eslogger's own: eslogger's envelope and `n`, without Mac Monitor's fields.
    ///
    /// - Parameter n: Its `n`.
    /// - Returns: The record's object.
    private func esloggerJSON(_ n: Int) -> [String: Any] {
        ["schema_version": 1, "event_type": 15, "event": ["exit": ["stat": 0]], "n": n]
    }
    
    /// Records as JSON text, as Mac Monitor's exports write them.
    ///
    /// - Parameters:
    ///   - records: The records.
    ///   - pretty: Pretty-printed, as Mac Monitor's pretty export writes them.
    /// - Returns: Each record's text.
    /// - Throws: The error serializing a record.
    private func text(_ records: [[String: Any]], pretty: Bool = false) throws -> [String] {
        try records.map { try jsonText($0, pretty: pretty) }
    }
    
    /// Validate a file holding `text`.
    ///
    /// - Parameters:
    ///   - text: The file's contents.
    ///   - limit: The most issues to keep.
    /// - Returns: The report.
    /// - Throws: The error writing or validating the file.
    private func validate(_ text: String, keepingIssues limit: Int = 100) throws -> TelemetryValidation {
        try validator.validate(traceAt: try temporaryFile(containing: text, named: "trace.jsonl"), keepingIssues: limit)
    }
    
    // MARK: Shapes
    
    /// JSON Lines, pretty records joined by "\n", compact and pretty JSON arrays, and a byte order mark all give the
    /// same report, but for the lines the issues are on.
    ///
    /// - Throws: The error writing or validating a trace.
    func testEveryShapeGivesTheSameReport() throws {
        let records = [record(1), record("two"), record(3)]
        let array = try JSONSerialization.data(withJSONObject: records, options: [.sortedKeys])
        let prettyArray = try JSONSerialization.data(withJSONObject: records, options: [.prettyPrinted, .sortedKeys])
        let shapes = ["jsonl": try text(records).joined(separator: "\n") + "\n",
                      "pretty": try text(records, pretty: true).joined(separator: "\n"),
                      "array": String(decoding: array, as: UTF8.self),
                      "pretty array": String(decoding: prettyArray, as: UTF8.self),
                      "byte order mark": "\u{FEFF}" + (try text(records).joined(separator: "\n"))]
        for (shape, contents) in shapes {
            let report = try validate(contents)
            XCTAssertEqual([report.records, report.valid, report.invalid, report.malformed], [3, 2, 1, 0], shape)
            XCTAssertEqual(report.issues.map(\.kind.description), ["n: expected integer, found string"], shape)
            XCTAssertEqual(report.issues.map(\.value), ["\"two\""], shape)
        }
        XCTAssertEqual(try validate(shapes["jsonl"]!).issues.map(\.line), [2])
        XCTAssertEqual(try validate(shapes["pretty"]!).issues.map(\.line), [6], "The record's first line")
    }
    
    /// A record cut short, a line that isn't JSON, and braces around text that isn't JSON are malformed, each on its
    /// own line.
    ///
    /// - Throws: The error writing or validating the trace.
    func testMalformedRecordsAreNumberedByLine() throws {
        let good = try text([record(1)])[0]
        let report = try validate([good, "not a record", good, "{\"n\": tru}", good, "{\"n\":"].joined(separator: "\n"))
        XCTAssertEqual([report.records, report.valid, report.invalid, report.malformed], [6, 3, 0, 3])
        XCTAssertEqual(report.issues.map(\.line), [2, 4, 6])
        XCTAssertEqual(report.issues[0].description, "line 2: incomplete or malformed JSON")
        XCTAssertTrue(report.issues[1].description.hasPrefix("line 4: not JSON ("), report.issues[1].description)
        XCTAssertEqual(report.issues[2].description, "line 6: incomplete or malformed JSON")
        XCTAssertFalse(report.isValid)
    }
    
    /// A record that isn't JSON is reported on the line where reading it stopped, without the place the parser names,
    /// which counts from the record's first line: the same mistake in two records is one kind of issue. A record on
    /// its own keeps the place.
    ///
    /// - Throws: The error writing or validating the trace.
    func testNotJSONIsOnTheLineItStops() throws {
        let good = try text([record(1)], pretty: true)[0], broken = "{\n  \"n\" : 1,\n  \"b\" : ,\n  \"c\" : 2\n}"
        let report = try validate([good, broken, "{\"n\": tru}", "{\"nn\": tru}"].joined(separator: "\n"))
        XCTAssertEqual([report.records, report.valid, report.malformed], [4, 1, 3])
        XCTAssertEqual(report.issues.map(\.line), [8, 11, 12], "The broken value's line, the record's third")
        XCTAssertEqual(report.issues.filter { $0.description.contains("around") }, [])
        XCTAssertEqual(report.issueCounts.values.sorted(), [1, 2])
        
        let alone = try validator.issues(inRecord: Data(broken.utf8))
        XCTAssertEqual(alone.map(\.line), [nil])
        XCTAssertTrue(alone.first?.description.contains(" around ") ?? false, "\(alone)")
    }
    
    /// A file with no records, empty or only blank lines, has no issues but isn't a valid trace: an export that came
    /// out empty mustn't pass.
    ///
    /// - Throws: The error writing or validating the trace.
    func testEmptyFileIsNotValid() throws {
        for contents in ["", "\n \n\t\n", "[]"] {
            let report = try validate(contents)
            XCTAssertEqual([report.records, report.issueTotal], [0, 0], contents)
            XCTAssertFalse(report.isValid, contents)
            XCTAssertEqual(report.summary(fileName: "trace.jsonl"),
                           "trace.jsonl: no records (Mac Monitor telemetry 1.0.0).", contents)
        }
    }
    
    /// Only files are validated: a folder is refused.
    ///
    /// - Throws: The error making the folder.
    func testFolderIsNotAFile() throws {
        XCTAssertThrowsError(try validator.validate(traceAt: try makeTemporaryDirectory())) { error in
            guard case TraceImporter.Failure.notAFile = error else {
                return XCTFail("Expected notAFile, found \(error)")
            }
        }
    }
    
    // MARK: Reports
    
    /// A thousand records with the same problem keep the first issues, count every one, and are one kind of issue.
    ///
    /// - Throws: The error writing or validating the trace.
    func testIssueLimitAndKinds() throws {
        var seen = 0
        let url = try temporaryFile(containing: try text((0..<1_000).map { record("\($0)") }).joined(separator: "\n"))
        let report = try validator.validate(traceAt: url, keepingIssues: 10, onIssue: { _ in seen += 1 })
        XCTAssertEqual(report.issues.count, 10)
        XCTAssertEqual(report.issueTotal, 1_000)
        XCTAssertEqual(seen, 1_000)
        XCTAssertEqual(report.issueCounts,
                       [TelemetryIssue.Kind(path: "n", problem: "expected integer, found string"): 1_000])
        XCTAssertEqual(report.summary(fileName: "trace.jsonl"),
                       "trace.jsonl: 1,000 records: 1,000 invalid; 1,000 issues (Mac Monitor telemetry 1.0.0).")
        XCTAssertTrue(report.report(fileName: "trace.jsonl").contains("  1,000 x n: expected integer, found string"))
        XCTAssertTrue(report.report(fileName: "trace.jsonl").contains("First 10 of 1,000 issues:"))
    }
    
    /// A record's issues past those kept are counted by kind without being made, so a record of millions of broken
    /// values can't take gigabytes: the report counts every one, and `onIssue` gets the ones kept.
    ///
    /// - Throws: The error writing or validating the trace.
    func testIssuesPastTheKeptOnesAreCounted() throws {
        let broken = record(1).merging(["list": Array(repeating: "x", count: 100_000)]) { $1 }
        let url = try temporaryFile(containing: try text([broken, record("two")]).joined(separator: "\n"))
        var seen = 0
        let report = try validator.validate(traceAt: url, keepingIssues: 10, onIssue: { _ in seen += 1 })
        XCTAssertEqual([report.records, report.invalid, report.issueTotal, report.issues.count], [2, 2, 100_001, 10])
        XCTAssertEqual(seen, TelemetryValidator.minIssuesKeptPerRecord + 1)
        XCTAssertEqual(report.issueCounts, [
            TelemetryIssue.Kind(path: "list[]", problem: "expected integer, found string"): 100_000,
            TelemetryIssue.Kind(path: "n", problem: "expected integer, found string"): 1,
        ])
        XCTAssertEqual(report.issues.last?.description, "line 1: list[9]: expected integer, found \"x\"")
    }
    
    /// Text a trace chooses is cut before it's kept: a megabyte telemetry version, and a megabyte key that's an
    /// identifier or isn't, take no more of the report than short ones, so the report's size doesn't follow the file's.
    ///
    /// - Throws: The error writing or validating the trace.
    func testTraceTextIsCut() throws {
        let long = String(repeating: "a", count: 1 << 20)
        let cut = String(repeating: "a", count: JSONText.maxQuoted) + "…", quoted = "\"\(cut)\""
        let report = try validate(try text([record(1, version: long), record(2).merging([long: 1]) { $1 },
                                            record(3).merging([long + "-": 1]) { $1 }]).joined(separator: "\n"))
        XCTAssertEqual(report.telemetryVersions, [cut, "1.0.0"])
        XCTAssertEqual(report.issues.map(\.description), ["line 1: telemetry_version: \(quoted) isn't \"1.0.0\"",
                                                          "line 2: [\(quoted)]: not in the schema",
                                                          "line 3: [\(quoted)]: not in the schema"])
        XCTAssertEqual(report.hint(), "This trace is telemetry \(quoted); validate it with the schema attached to the "
                        + "release that wrote it.")
        XCTAssertLessThan(report.report(fileName: "trace.jsonl").utf8.count, 2_048)
    }
    
    /// Cancelling stops before the next record, and the report says it stopped; progress ends at the file's size.
    ///
    /// - Throws: The error writing or validating the trace.
    func testCancellationAndProgress() throws {
        let url = try temporaryFile(containing: try text((0..<5).map { record($0) }).joined(separator: "\n"))
        var asked = 0
        let stopped = try validator.validate(traceAt: url, isCancelled: { asked += 1; return asked > 3 })
        XCTAssertEqual(stopped.records, 3)
        XCTAssertTrue(stopped.stoppedEarly)
        XCTAssertFalse(stopped.isValid)
        
        var reports: [(Int64, Int64)] = []
        let finished = try validator.validate(traceAt: url, progress: { reports.append(($0, $1)) })
        XCTAssertTrue(finished.isValid)
        let size = try XCTUnwrap(try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64)
        XCTAssertEqual(reports.last?.0, size)
        XCTAssertEqual(reports.last?.1, size)
    }
    
    /// eslogger's own JSON gets a hint to check its eslogger fields, ending with the front end's own advice; an export
    /// from before telemetry versions a hint to export it again; and another telemetry version a hint to use its own
    /// schema. JSON that's neither eslogger's nor Mac Monitor's gets none.
    ///
    /// - Throws: The error reading a fixture, or writing or validating a trace.
    func testHints() throws {
        let eslogger = try validate(try text([esloggerJSON(1), esloggerJSON(2)]).joined(separator: "\n"))
        let esloggerHint = "This looks like eslogger's JSON, without Mac Monitor's fields."
        XCTAssertEqual(eslogger.hint(), "\(esloggerHint) Check only the keys eslogger writes, in eslogger mode.")
        XCTAssertEqual(eslogger.hint(esloggerAdvice: "Run it with --eslogger."),
                       "\(esloggerHint) Run it with --eslogger.")
        XCTAssertTrue(eslogger.report(fileName: "trace.jsonl", esloggerAdvice: "Run it with --eslogger.")
            .contains("\n\(esloggerHint) Run it with --eslogger.\n"))
        
        let old = try validator.validate(traceAt: try fixtureURL("macmonitor-2.1-exit.jsonl"))
        XCTAssertEqual(old.hint(), "No record names a telemetry version: this looks like an export from before Mac "
                        + "Monitor 2.2.0, which no schema describes. Open it in Mac Monitor with File > Open Trace… "
                        + "and export it again to check it.")
        
        let newer = try validate(try text([record(1, version: "9.9.9")])[0])
        XCTAssertEqual(newer.telemetryVersions, ["9.9.9"])
        XCTAssertEqual(newer.issues.map(\.description), ["line 1: telemetry_version: \"9.9.9\" isn't \"1.0.0\""])
        XCTAssertEqual(newer.hint(),
                       "This trace is telemetry \"9.9.9\"; validate it with the schema attached to the release "
                        + "that wrote it.")
        
        XCTAssertNil(try validate(try text([record(1)])[0]).hint())
        XCTAssertNil(try validate(try text([["x": 1], ["a": 1]]).joined(separator: "\n")).hint(),
                     "JSON that's neither eslogger's nor Mac Monitor's")
    }
    
    /// A trace looks like eslogger's when every record that's JSON has eslogger's envelope without Mac Monitor's
    /// fields: the app then offers to check its eslogger fields, which never looks like eslogger's again. An empty or
    /// malformed trace, JSON without eslogger's envelope, or one record with Mac Monitor's fields, doesn't.
    ///
    /// - Throws: The error writing or validating a trace.
    func testLooksLikeESLogger() throws {
        let eslogger = try text([esloggerJSON(1), esloggerJSON(2)]).joined(separator: "\n")
        XCTAssertTrue(try validate(eslogger).looksLikeESLogger)
        XCTAssertTrue(try validate(eslogger + "\n{\"n\":").looksLikeESLogger, "A record cut short isn't counted")
        let url = try temporaryFile(containing: eslogger)
        let checked = try TelemetryValidator(schema: Data(schema.utf8), mode: .eslogger).validate(traceAt: url)
        XCTAssertFalse(checked.looksLikeESLogger)
        XCTAssertNil(checked.hint())
        
        XCTAssertFalse(try validate("").looksLikeESLogger)
        XCTAssertFalse(try validate("{\"n\":").looksLikeESLogger)
        XCTAssertFalse(try validate(try text([esloggerJSON(1), record(2)]).joined(separator: "\n")).looksLikeESLogger)
        XCTAssertFalse(try validate(try text([["x": 1], ["a": 1]]).joined(separator: "\n")).looksLikeESLogger,
                       "JSON without eslogger's envelope")
        XCTAssertFalse(try validator.validate(traceAt: try fixtureURL("macmonitor-2.1-exit.jsonl")).looksLikeESLogger,
                       "Mac Monitor 2.1's export")
    }
    
    /// The report is the summary, the hint, then its details: the kinds of issue and the issues kept, which are empty
    /// for a valid trace.
    ///
    /// - Throws: The error writing or validating a trace.
    func testReportDetails() throws {
        let valid = try validate(try text([record(1)])[0])
        XCTAssertEqual(valid.details, "")
        XCTAssertEqual(valid.report(fileName: "trace.jsonl"), valid.summary(fileName: "trace.jsonl"))
        
        let invalid = try validate(try text([record("one"), record(2, version: "9.9.9"), record("three")])
            .joined(separator: "\n"), keepingIssues: 2)
        XCTAssertEqual(invalid.details, """
            Issues by kind:
              2 x n: expected integer, found string
              1 x telemetry_version: isn't "1.0.0"

            First 2 of 3 issues:
              line 1: n: expected integer, found "one"
              line 2: telemetry_version: "9.9.9" isn't "1.0.0"
            """)
        XCTAssertEqual(invalid.report(fileName: "trace.jsonl"),
                       [invalid.summary(fileName: "trace.jsonl"), try XCTUnwrap(invalid.hint()), "", invalid.details]
                        .joined(separator: "\n"))
    }
    
    /// Records checked a batch at a time in parallel give the same report, in file order, as one at a time.
    ///
    /// - Throws: The error writing or validating the trace.
    func testParallelBatchesKeepFileOrder() throws {
        let records = (0..<1_200).map { $0 % 7 == 0 ? record("\($0)") : record($0) }
        let url = try temporaryFile(containing: try text(records).joined(separator: "\n"))
        /// The trace's report, checked `batchSize` records at a time.
        func report(batchSize: Int) throws -> TelemetryValidation {
            try validator.validate(try TraceRecordReader(url: url), keepingIssues: .max, batchSize: batchSize,
                                   isCancelled: { false }, progress: nil, onIssue: nil)
        }
        let parallel = try report(batchSize: 500), serial = try report(batchSize: 1)
        XCTAssertEqual(parallel.issues, serial.issues)
        let lines = parallel.issues.compactMap(\.line)
        XCTAssertEqual(lines, lines.sorted())
        XCTAssertEqual([parallel.records, parallel.valid, parallel.invalid], [1_200, 1_028, 172])
    }
}
