//
//  TelemetrySchemaIssueTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Real records, broken on purpose
/// Checks real records against the schema the framework bundles, through the calls the app and the command line make:
/// the fixtures' exports validate as a trace, and each targeted break of one is reported once, at the path it broke,
/// with what's wrong there, in a record on its own and by line in a trace.
final class TelemetrySchemaIssueTests: XCTestCase {
    /// A step into a JSON value: a key of an object, or an index of an array.
    private enum Step: ExpressibleByStringLiteral, ExpressibleByIntegerLiteral {
        case key(String), index(Int)
        
        /// A key, written as a string literal.
        ///
        /// - Parameter key: The key.
        init(stringLiteral key: String) { self = .key(key) }
        
        /// An index, written as an integer literal.
        ///
        /// - Parameter index: The index.
        init(integerLiteral index: Int) { self = .index(index) }
    }
    
    /// The schema the framework bundles, checking every key, as the app and the command line load it.
    private var validator: TelemetryValidator!
    
    /// Load the bundled schema.
    ///
    /// - Throws: The error reading or compiling it.
    override func setUpWithError() throws {
        validator = try TelemetryValidator.bundled()
    }
    
    // MARK: Valid
    
    /// Every fixture's export, written as a JSONL trace, is valid, and the report says so.
    ///
    /// - Throws: The error reading a fixture, or writing or validating the trace.
    func testFixtureExportsValidateAsATrace() throws {
        let exports = try fixtureExports()
        let url = try temporaryFile(containing: exports.map(\.json).joined(separator: "\n") + "\n",
                                    named: "fixtures.jsonl")
        let report = try validator.validate(traceAt: url)
        XCTAssertTrue(report.isValid, report.report(fileName: url.lastPathComponent))
        XCTAssertEqual([report.records, report.valid, report.issueTotal], [exports.count, exports.count, 0])
        XCTAssertEqual(report.telemetryVersions, [TelemetrySchema.version])
        XCTAssertNil(report.hint())
        XCTAssertEqual(report.summary(fileName: url.lastPathComponent),
                       "fixtures.jsonl: \(exports.count) records, all valid "
                        + "(Mac Monitor telemetry \(TelemetrySchema.version)).")
    }
    
    // MARK: Broken records
    
    /// A value of the wrong type or format is reported at its own path: in an event's process, its arguments, the
    /// envelope, and a nullable object.
    ///
    /// - Throws: The error reading a fixture.
    func testBrokenValuesNameTheirPath() throws {
        let records = try exportedRecords()
        let exec = try first("exec", in: records)
        let cdhash = try XCTUnwrap(try value(at: ["event", "exec", "target", "cdhash"], in: exec) as? String)
        let process = "#/$defs/process/properties"
        
        check(exec, ["event", "exec", "target", "cdhash"], cdhash.lowercased(),
              "event.exec.target.cdhash: \"\(cdhash.lowercased())\" doesn't match \(SchemaPattern.cdhash.rawValue)",
              at: "\(process)/cdhash")
        check(exec, ["event", "exec", "args", 0], 7, "event.exec.args[0]: expected string, found 7",
              at: "#/$defs/exec_event/properties/args/items")
        check(exec, ["process", "ppid"], "1", "process.ppid: expected integer, found \"1\"", at: "\(process)/ppid")
        check(exec, ["process", "is_platform_binary"], 1, "process.is_platform_binary: expected boolean, found 1",
              at: "\(process)/is_platform_binary")
        check(exec, ["time"], "2026-01-01T16:42:30Z",
              "time: \"2026-01-01T16:42:30Z\" doesn't match \(SchemaPattern.timespec.rawValue)",
              at: "#/properties/time")
        check(exec, ["process", "start_time"], "2026-01-01T16:42:30.765276635Z",
              "process.start_time: \"2026-01-01T16:42:30.765276635Z\" doesn't match \(SchemaPattern.timeval.rawValue)",
              at: "\(process)/start_time")
        check(exec, ["telemetry_version"], "9.9.9", "telemetry_version: \"9.9.9\" isn't \"\(TelemetrySchema.version)\"",
              at: "#/properties/telemetry_version")
        check(exec, ["es_event_type"], "ES_EVENT_TYPE_NOTIFY_NOPE",
              "es_event_type: \"ES_EVENT_TYPE_NOTIFY_NOPE\" isn't one of the schema's values",
              at: "#/properties/es_event_type")
        check(exec, ["thread", "thread_id"], "900101", "thread.thread_id: expected integer, found \"900101\"",
              at: "#/$defs/thread/properties/thread_id")
        
        let member = try first("od_group_add", in: records) { $0["member"] is [String: Any] }
        check(member, ["event", "od_group_add", "member", "member_type"], "0",
              "event.od_group_add.member.member_type: expected integer, found \"0\"",
              at: "#/$defs/od_member/properties/member_type")
    }
    
    /// A missing key, a key the schema doesn't have, an event Mac Monitor doesn't record, two events, and a value
    /// that's none of a key's alternatives are each reported at their own path.
    ///
    /// - Throws: The error reading a fixture.
    func testBrokenObjectsNameTheirPath() throws {
        let records = try exportedRecords()
        let exec = try first("exec", in: records) { $0["launched_by_parent"] is [String: Any] }
        let fork = try value(at: ["event", "fork"], in: try first("fork", in: records))
        
        check(exec, ["event", "exec", "target", "audit_token", "pid"], nil,
              "event.exec.target.audit_token.pid: missing", at: "#/$defs/audit_token/properties/pid")
        check(exec, ["telemetry_version"], nil, "telemetry_version: missing", at: "#/properties/telemetry_version")
        check(exec, ["event", "exec", "target", "executable", "extra"], 1,
              "event.exec.target.executable.extra: not in the schema", at: "#/$defs/file")
        check(exec, ["event"], ["od_attribute_set": [String: Any]()],
              "event.od_attribute_set: Mac Monitor doesn't record od_attribute_set events", at: "#/$defs/event")
        check(exec, ["event", "fork"], fork, "event: has 2 keys, expected 1", at: "#/$defs/event")
        check(exec, ["event", "exec", "launched_by_parent"], "zsh",
              "event.exec.launched_by_parent: expected null or object, found \"zsh\"",
              at: "#/$defs/exec_event/properties/launched_by_parent")
        check(exec, ["event", "exec", "launched_by_parent", "source"], "guess",
              "event.exec.launched_by_parent.source: \"guess\" isn't one of the schema's values",
              at: "#/$defs/launched_by_parent/properties/source")
        
        let user = try first("od_create_user", in: records) { $0["instigator_token"] is [String: Any] }
        check(user, ["event", "od_create_user", "instigator_token", "pid"], nil,
              "event.od_create_user.instigator_token.pid: missing", at: "#/$defs/audit_token/properties/pid")
    }
    
    /// In a trace, each broken record's issue names the line it starts on, a record cut short is malformed, and the
    /// report counts records and issues by kind: in JSONL and in pretty-printed records alike.
    ///
    /// - Throws: The error reading a fixture, or writing or validating the trace.
    func testBrokenTraceCountsIssuesByLine() throws {
        var records = try exportedRecords()
        XCTAssertGreaterThan(records.count, 5)
        let cdhash = try XCTUnwrap(try value(at: ["process", "cdhash"], in: records[2]) as? String).lowercased()
        records[2] = edited(records[2], at: ["process", "cdhash"], to: cdhash)
        records[5] = edited(records[5], at: ["process", "audit_token", "pid"], to: nil)
        let (valid, version) = (records.count - 2, TelemetrySchema.version)
        let pattern = "doesn't match \(SchemaPattern.cdhash.rawValue)"
        
        for pretty in [false, true] {
            let texts = try records.map { try jsonText($0, pretty: pretty) }
            /// The line each record starts on, and after them the line the record cut short starts on. A pretty empty
            /// array or object has an empty line.
            var starts = [1]
            for text in texts {
                starts.append(starts.last! + text.split(separator: "\n", omittingEmptySubsequences: false).count)
            }
            let contents = (texts + [String(texts[0].prefix(40))]).joined(separator: "\n")
            let report = try validator.validate(traceAt: try temporaryFile(containing: contents, named: "broken.jsonl"))
            let shape = pretty ? "pretty" : "JSONL"
            
            XCTAssertEqual([report.records, report.valid, report.invalid, report.malformed],
                           [records.count + 1, valid, 2, 1], shape)
            XCTAssertEqual(report.issues.map(\.description), [
                "line \(starts[2]): process.cdhash: \"\(cdhash)\" \(pattern)",
                "line \(starts[5]): process.audit_token.pid: missing",
                "line \(starts[records.count]): incomplete or malformed JSON",
            ], shape)
            XCTAssertEqual(report.issueCounts, [
                TelemetryIssue.Kind(path: "process.cdhash", problem: pattern): 1,
                TelemetryIssue.Kind(path: "process.audit_token.pid", problem: "missing"): 1,
                TelemetryIssue.Kind(path: "", problem: "incomplete or malformed JSON"): 1,
            ], shape)
            XCTAssertEqual(report.summary(fileName: "broken.jsonl"),
                           "broken.jsonl: \(records.count + 1) records: \(valid) valid, 2 invalid, 1 malformed; "
                            + "3 issues (Mac Monitor telemetry \(version)).", shape)
            XCTAssertFalse(report.isValid, shape)
        }
    }
    
    /// eslogger's own records are valid in eslogger mode, and its issues there are a Mac Monitor field that's present
    /// and an eslogger field that's missing. Checking every key, they get the hint to use eslogger mode.
    ///
    /// - Throws: The error reading the fixture, or loading or validating with the schema.
    func testESLoggerRecordsInESLoggerMode() throws {
        let url = try fixtureURL("eslogger-od.jsonl"), version = TelemetrySchema.version
        let eslogger = try TelemetryValidator.bundled(mode: .eslogger)
        let asESLogger = try eslogger.validate(traceAt: url)
        XCTAssertEqual(asESLogger.summary(fileName: url.lastPathComponent),
                       "eslogger-od.jsonl: 11 records, all valid (eslogger's fields of Mac Monitor telemetry "
                        + "\(version)).")
        XCTAssertNil(asESLogger.hint())
        
        let asMacMonitor = try validator.validate(traceAt: url)
        XCTAssertEqual([asMacMonitor.records, asMacMonitor.invalid], [11, 11])
        XCTAssertEqual(asMacMonitor.issueCounts[TelemetryIssue.Kind(path: "telemetry_version", problem: "missing")], 11)
        XCTAssertEqual(asMacMonitor.hint(), "This looks like eslogger's JSON, without Mac Monitor's fields. "
                        + TelemetryValidation.esloggerAdvice)
        
        let user = try first("od_create_user", in: try fixtureRecords("eslogger-od.jsonl"))
        let event = "#/$defs/od_create_user_event/properties"
        check(user, ["event", "od_create_user", "error_code_human"], "Success",
              "event.od_create_user.error_code_human: Mac Monitor field in an eslogger record",
              at: "\(event)/error_code_human", with: eslogger)
        check(user, ["telemetry_version"], version, "telemetry_version: Mac Monitor field in an eslogger record",
              at: "#/properties/telemetry_version", with: eslogger)
        check(user, ["event", "od_create_user", "node_name"], nil, "event.od_create_user.node_name: missing",
              at: "\(event)/node_name", with: eslogger)
        check(user, ["process", "signing_id"], nil, "process.signing_id: missing",
              at: "#/$defs/process/properties/signing_id", with: eslogger)
    }
    
    // MARK: Helpers
    
    /// Assert that a valid record, changed in one place, has exactly one issue: the one expected.
    ///
    /// - Parameters:
    ///   - record: The record, which must be valid as it is.
    ///   - path: Where to change it.
    ///   - value: The value put there, or `nil` to remove the key.
    ///   - expected: The issue, as the app and the command line show it.
    ///   - location: The schema location the issue names.
    ///   - validator: The validator, or the bundled schema checking every key.
    ///   - file: The caller's file.
    ///   - line: The caller's line.
    private func check(_ record: [String: Any], _ path: [Step], _ value: Any?, _ expected: String,
                       at location: String, with validator: TelemetryValidator? = nil,
                       file: StaticString = #filePath, line: UInt = #line) {
        let validator = validator ?? self.validator!
        do {
            let original = try JSONSerialization.data(withJSONObject: record)
            XCTAssertEqual(validator.issues(inRecord: original).map(\.description), [], "Before the change",
                           file: file, line: line)
            let broken = try JSONSerialization.data(withJSONObject: edited(record, at: path, to: value))
            let issues = validator.issues(inRecord: broken)
            XCTAssertEqual(issues.map(\.description), [expected], file: file, line: line)
            XCTAssertEqual(issues.map(\.schemaLocation), [location], expected, file: file, line: line)
            XCTAssertEqual(issues.map(\.line), [nil], "A record on its own has no line", file: file, line: line)
        } catch {
            XCTFail("\(expected): \(error)", file: file, line: line)
        }
    }
    
    /// The fixtures' exports (``fixtureExports()``), parsed.
    ///
    /// - Returns: Each export's object, in the fixtures' order.
    /// - Throws: The error reading a fixture, or an `XCTest` failure if an export isn't a JSON object.
    private func exportedRecords() throws -> [[String: Any]] {
        try fixtureExports().map { label, json in
            try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any], label)
        }
    }
    
    /// The first record of an event type whose event will do.
    ///
    /// - Parameters:
    ///   - name: The event's key, such as `exec`.
    ///   - records: The records.
    ///   - matches: Whether a record's event object will do.
    /// - Returns: The record.
    /// - Throws: An `XCTest` failure if none will do.
    private func first(_ name: String, in records: [[String: Any]],
                       where matches: ([String: Any]) -> Bool = { _ in true }) throws -> [String: Any] {
        try XCTUnwrap(records.first { record in
            ((record["event"] as? [String: Any])?[name] as? [String: Any]).map(matches) ?? false
        }, "No \(name) record will do")
    }
    
    /// The value at a path in a JSON value.
    ///
    /// - Parameters:
    ///   - path: The path.
    ///   - json: The JSON value.
    /// - Returns: The value there.
    /// - Throws: An `XCTest` failure if there's none.
    private func value(at path: [Step], in json: Any) throws -> Any {
        try path.reduce(json) { found, step in
            switch step {
            case .key(let key):
                return try XCTUnwrap((found as? [String: Any])?[key], "No \(key)")
            case .index(let index):
                let array = try XCTUnwrap(found as? [Any], "No array for [\(index)]")
                return try XCTUnwrap(array.indices.contains(index) ? array[index] : nil, "No [\(index)]")
            }
        }
    }
    
    /// A record changed in one place.
    ///
    /// - Parameters:
    ///   - record: The record.
    ///   - path: Where to change it: through keys and indexes it has, to a key it may not have yet.
    ///   - value: The value put there, or `nil` to remove the key.
    /// - Returns: The changed record.
    private func edited(_ record: [String: Any], at path: [Step], to value: Any?) -> [String: Any] {
        /// The JSON value `current` with the value at `path` replaced.
        func replacing(in current: Any?, at path: ArraySlice<Step>) -> Any? {
            guard let step = path.first else { return value }
            switch step {
            case .key(let key):
                var object = current as? [String: Any] ?? [:]
                object[key] = replacing(in: object[key], at: path.dropFirst())
                return object
            case .index(let index):
                var array = current as? [Any] ?? []
                array[index] = replacing(in: array[index], at: path.dropFirst()) ?? NSNull()
                return array
            }
        }
        return replacing(in: record, at: path[...]) as? [String: Any] ?? [:]
    }
}
