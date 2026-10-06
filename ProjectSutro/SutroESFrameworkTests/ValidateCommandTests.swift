//
//  ValidateCommandTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - macmonitor validate
/// Pins `macmonitor validate`, from its command line to its report and exit status, against the schema the framework
/// bundles: a valid export, an invalid record, a malformed one, a trace with no records, eslogger's own JSON with and
/// without `--eslogger`, traces that can't be read, a check that's stopped, output that can't be written, and text
/// from the trace that would drive a terminal, forge a line of the report, or make it megabytes.
final class ValidateCommandTests: XCTestCase {
    /// One run of `validate`.
    private struct Run {
        /// How it ended.
        let outcome: ValidateCommand.Outcome
        /// What it wrote to standard output.
        let report: String
    }
    
    /// Run a `macmonitor` command line that must be `validate`.
    ///
    /// - Parameters:
    ///   - arguments: The arguments after `validate`.
    ///   - output: Standard output.
    ///   - isCancelled: Asked before each record.
    /// - Returns: The run.
    /// - Throws: ``CommandLineUsageError``, or an `XCTest` failure if the line isn't `validate`.
    private func validate(_ arguments: String..., output: BufferOutput = BufferOutput(),
                          isCancelled: @escaping () -> Bool = { false }) throws -> Run {
        let parsed = try CommandLineParser.parse(["validate"] + arguments)
        guard case .validate(let invocation) = parsed else {
            XCTFail("'validate \(arguments.joined(separator: " "))' is \(parsed), not validate.")
            throw CommandLineUsageError("Not validate.")
        }
        let outcome = ValidateCommand(output: output, isCancelled: isCancelled).run(invocation)
        return Run(outcome: outcome, report: output.text)
    }
    
    /// The fixtures' exports, parsed.
    ///
    /// - Returns: Each export's object, in the fixtures' order.
    /// - Throws: The error reading a fixture, or an `XCTest` failure if an export isn't a JSON object.
    private func exportedRecords() throws -> [[String: Any]] {
        try fixtureExports().map { label, json in
            try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any], label)
        }
    }
    
    /// Records written as a trace.
    ///
    /// - Parameters:
    ///   - records: The records.
    ///   - pretty: Pretty-printed records, as the pretty export writes them, else JSON Lines.
    ///   - name: The file's name.
    /// - Returns: The trace's path.
    /// - Throws: The error serializing a record or writing the file.
    private func trace(_ records: [[String: Any]], pretty: Bool = false, named name: String = "trace.jsonl") throws
        -> String {
        try temporaryFile(containing: try records.map { try jsonText($0, pretty: pretty) }.joined(separator: "\n")
                            + "\n", named: name).path
    }
    
    // MARK: Valid and invalid
    
    /// Mac Monitor's exports of the fixtures are valid, as JSON Lines and as pretty records: exit 0, and a report of
    /// one line named by the path as typed.
    ///
    /// - Throws: The error reading a fixture or writing a trace.
    func testAValidExportExits0() throws {
        let records = try exportedRecords(), version = TelemetrySchema.version
        for pretty in [false, true] {
            let path = try trace(records, pretty: pretty)
            let run = try validate(path)
            XCTAssertEqual(run.outcome, .valid)
            XCTAssertEqual(run.outcome.exit, .success)
            XCTAssertEqual(run.report,
                           "\(path): \(records.count) records, all valid (Mac Monitor telemetry \(version)).\n")
        }
    }
    
    /// A record with a value of the wrong type makes the trace invalid: exit 65, and the report names the line the
    /// record starts on, the path of the value, and what's wrong with it.
    ///
    /// - Throws: The error reading a fixture or writing the trace.
    func testAnInvalidRecordExits65() throws {
        var records = try exportedRecords()
        var process = try XCTUnwrap(records[1]["process"] as? [String: Any])
        process["ppid"] = "1"
        records[1]["process"] = process
        let path = try trace(records, named: "broken.jsonl")
        let run = try validate(path)
        XCTAssertEqual(run.outcome, .invalid)
        XCTAssertEqual(run.outcome.exit, .dataError)
        XCTAssertEqual(run.report, """
            \(path): \(records.count) records: \(records.count - 1) valid, 1 invalid; 1 issue (Mac Monitor telemetry \
            \(TelemetrySchema.version)).
            
            Issues by kind:
              1 x process.ppid: expected integer, found string
            
            Issues:
              line 2: process.ppid: expected integer, found "1"
            
            """)
    }
    
    /// A record cut short is malformed, on the line it starts: exit 65.
    ///
    /// - Throws: The error reading a fixture or writing the trace.
    func testAMalformedLineExits65() throws {
        let lines = try fixtureExports().prefix(3).map(\.json)
        let path = try temporaryFile(containing: [lines[0], String(lines[1].prefix(40)), lines[2]]
                                        .joined(separator: "\n") + "\n", named: "cut.jsonl").path
        let run = try validate(path)
        XCTAssertEqual(run.outcome, .invalid)
        XCTAssertEqual(run.outcome.exit, .dataError)
        XCTAssertTrue(run.report.hasPrefix("\(path): 3 records: 2 valid, 1 malformed; 1 issue "), run.report)
        XCTAssertTrue(run.report.hasSuffix("\nIssues:\n  line 2: incomplete or malformed JSON\n"), run.report)
    }
    
    /// A trace with no records (an empty file, blank lines, or an empty array) isn't valid: exit 65, so an export
    /// that came out empty fails a check.
    ///
    /// - Throws: The error writing a trace.
    func testATraceWithNoRecordsExits65() throws {
        for contents in ["", "\n \n", "[]"] {
            let path = try temporaryFile(containing: contents, named: "empty.jsonl").path
            let run = try validate(path)
            XCTAssertEqual(run.outcome, .invalid, contents)
            XCTAssertEqual(run.outcome.exit, .dataError, contents)
            XCTAssertEqual(run.report, "\(path): no records (Mac Monitor telemetry \(TelemetrySchema.version)).\n",
                           contents)
        }
    }
    
    /// eslogger's own JSON isn't Mac Monitor's, and the hint names `--eslogger`; with it, only eslogger's keys are
    /// checked, and the trace is valid.
    ///
    /// - Throws: An `XCTest` failure if the fixture is missing.
    func testESLoggerJSONWithAndWithoutTheOption() throws {
        let path = try fixtureURL("eslogger-od.jsonl").path, version = TelemetrySchema.version
        let full = try validate(path)
        XCTAssertEqual(full.outcome, .invalid)
        XCTAssertEqual(full.outcome.exit, .dataError)
        XCTAssertTrue(full.report.hasPrefix("\(path): 11 records: 11 invalid; "), full.report)
        XCTAssertTrue(full.report.contains("\nThis looks like eslogger's JSON, without Mac Monitor's fields. Add "
                                           + "--eslogger to check only the keys eslogger writes.\n"), full.report)
        
        for line in [["--eslogger", path], [path, "--eslogger"]] {
            let eslogger = try validate(line[0], line[1])
            XCTAssertEqual(eslogger.outcome, .valid)
            XCTAssertEqual(eslogger.report, "\(path): 11 records, all valid (eslogger's fields of Mac Monitor "
                                            + "telemetry \(version)).\n")
        }
    }
    
    // MARK: Traces that can't be read
    
    /// A folder, a pipe, a device, standard input, a missing file, an unreadable one and an empty path (which names no
    /// file, not the current folder) exit 66, saying why, and write nothing to standard output. None of them blocks.
    ///
    /// - Throws: The error making the files.
    func testTracesThatCantBeReadExit66() throws {
        let folder = try makeTemporaryDirectory()
        let fifo = folder.appendingPathComponent("fifo").path
        XCTAssertEqual(mkfifo(fifo, 0o600), 0)
        let locked = try temporaryFile(containing: "{}\n", named: "locked.jsonl").path
        XCTAssertEqual(chmod(locked, 0), 0)
        addTeardownBlock { chmod(locked, 0o600) }
        let missing = folder.appendingPathComponent("missing.jsonl").path
        
        let expected = [
            folder.path: "“\(folder.path)” couldn't be read: it isn't a regular file.",
            fifo: "“\(fifo)” couldn't be read: it isn't a regular file.",
            "/dev/null": "“/dev/null” couldn't be read: it isn't a regular file.",
            missing: "“\(missing)” couldn't be read: No such file or directory.",
            locked: "“\(locked)” couldn't be read: Permission denied.",
            "-": "validate reads a trace from a file, not standard input. Save it to a file, then validate that.",
            "": "“” couldn't be read: No such file or directory."
        ]
        for (path, message) in expected {
            let run = try validate(path)
            XCTAssertEqual(run.outcome, .failed(CommandLineFailure(.noInput, message)), path)
            XCTAssertEqual(run.outcome.exit?.rawValue, 66, path)
            XCTAssertEqual(run.report, "", path)
        }
    }
    
    // MARK: Stopping, output, and the schema
    
    /// A check that's cancelled stops before its next record and still writes the report so far, which says so: it
    /// has no exit status of its own, as `macmonitor` exits by the signal that stopped it.
    ///
    /// - Throws: The error reading a fixture or writing the trace.
    func testACancelledCheckStops() throws {
        let path = try trace(try exportedRecords())
        var asked = 0
        let run = try validate(path, isCancelled: {
            asked += 1
            return asked > 1
        })
        XCTAssertEqual(run.outcome, .stopped)
        XCTAssertNil(run.outcome.exit)
        XCTAssertEqual(run.report, "\(path): 1 record, all valid (Mac Monitor telemetry \(TelemetrySchema.version)). "
                                    + "Stopped before the end of the file.\n")
    }
    
    /// A closed pipe (`| head -1`) doesn't change the verdict: 0 for a valid trace, 65 for an invalid one. Any other
    /// write error exits 74. A schema that can't be read exits 70.
    ///
    /// - Throws: The error reading a fixture or writing a trace.
    func testOutputAndSchemaFailures() throws {
        let valid = try trace(try exportedRecords()), invalid = try fixtureURL("eslogger-exit.jsonl").path
        for (path, outcome) in [(valid, ValidateCommand.Outcome.valid), (invalid, .invalid)] {
            let closed = BufferOutput()
            closed.fail(with: .closed)
            XCTAssertEqual(try validate(path, output: closed).outcome, outcome, path)
        }
        let full = BufferOutput()
        full.fail(with: .failed(ENOSPC))
        XCTAssertEqual(try validate(valid, output: full).outcome, .failed(.output(ENOSPC)))
        XCTAssertEqual(ValidateCommand.Outcome.failed(.output(ENOSPC)).exit?.rawValue, 74)
        
        let output = BufferOutput()
        let missing = ValidateCommand(output: output, schema: { throw TelemetrySchemaError.missingResource })
        XCTAssertEqual(missing.run(ValidateInvocation(path: valid)), .failed(CommandLineFailure(
            .software, "Mac Monitor's telemetry schema is missing from its framework.")))
        XCTAssertEqual(output.text, "")
    }
    
    /// What a trace says is anyone's text, and so is its name: a telemetry version, an event's name or a file name
    /// that would drive a terminal is escaped in the report, and a newline in one can't start a line of its own, such
    /// as a forged summary.
    ///
    /// - Throws: The error reading a fixture or writing the trace.
    func testTheReportIsSafeForATerminal() throws {
        var records = try exportedRecords()
        let forged = "\nforged.jsonl: 1 record, all valid (Mac Monitor telemetry \(TelemetrySchema.version))."
        records[0][TelemetrySchema.versionKey] = "9\u{1B}]0;title\u{07}\u{202E}" + forged
        records[1]["event"] = ["a\nb": [String: Any]()]
        let path = try trace(records, named: "trace\u{1B}[2J" + forged)
        let run = try validate(path)
        XCTAssertEqual(run.outcome, .invalid)
        XCTAssertFalse(run.report.unicodeScalars.contains { $0 != "\n" && TerminalSafeText.needsEscape($0) },
                       run.report)
        let named = path.replacingOccurrences(of: "\u{1B}", with: #"\x1B"#).replacingOccurrences(of: "\n", with: #"\n"#)
        XCTAssertTrue(run.report.hasPrefix(named + ": "), run.report)
        XCTAssertTrue(run.report.contains(#"This trace is telemetry "9\u001b]0;title\u0007\u{202E}\nforged.jsonl: "#),
                      run.report)
        XCTAssertTrue(run.report.contains(#"event["a\nb"]: Mac Monitor doesn't record "a\nb" events"#), run.report)
        
        /// Every line is one the report writes: the summary, the hint, a blank line, the issues by kind, a blank line,
        /// and the issues, then the final newline.
        let report = try TelemetryValidator.bundled().validate(traceAt: URL(fileURLWithPath: path))
        XCTAssertEqual(run.report.split(separator: "\n", omittingEmptySubsequences: false).count,
                       7 + report.issueCounts.count + report.issues.count, run.report)
    }
    
    /// Text a trace chooses is cut before the report keeps it: a megabyte telemetry version, event name (an
    /// identifier or not) and key give a report of a few lines, not megabytes.
    ///
    /// - Throws: The error reading a fixture or writing the trace.
    func testLongTraceTextIsCut() throws {
        var records = try exportedRecords()
        let long = String(repeating: "a", count: 1 << 20)
        records[0][TelemetrySchema.versionKey] = long
        records[1]["event"] = [long: [String: Any]()]
        records[2]["event"] = [long + "-": [String: Any]()]
        records[3][long] = 1
        let run = try validate(try trace(records))
        XCTAssertEqual(run.outcome, .invalid)
        XCTAssertLessThan(run.report.utf8.count, 4_096, run.report)
        let quoted = "\"\(String(repeating: "a", count: JSONText.maxQuoted))…\""
        XCTAssertTrue(run.report.contains("event[\(quoted)]: Mac Monitor doesn't record \(quoted) events"), run.report)
        XCTAssertTrue(run.report.contains("This trace is telemetry \(quoted); "), run.report)
    }
}
