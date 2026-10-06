//
//  TelemetryValidator.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Telemetry validator
/// Checks records against Mac Monitor's telemetry schema (or another schema in the same subset of JSON Schema): one
/// record at a time, or a whole trace, streamed.
///
/// Shared by the app (Help > Telemetry Schema…), the `macmonitor` command line tool, and the tests that keep the
/// exports and the schema in step. Immutable once made, so one validator can check records on any number of threads.
public struct TelemetryValidator: @unchecked Sendable {
    /// Which of a record's keys are checked.
    public enum Mode: Sendable {
        /// Every key: a record Mac Monitor wrote.
        case macMonitor
        /// eslogger's keys only: a record eslogger wrote. Mac Monitor's keys aren't required, and one that's present is
        /// an issue.
        case eslogger
    }
    
    /// The most records checked at a time.
    static let batchSize = 500
    /// The most bytes of records checked at a time: a batch of large records is checked before it has ``batchSize``.
    static let batchBytes = 64 << 20
    /// How many of each record's issues a trace's check keeps in full, or as many as its report keeps if that's more:
    /// past them, a record's issues are only counted, by kind, so one record can't take gigabytes.
    public static let minIssuesKeptPerRecord = 1_000
    
    /// The compiled schema.
    let schema: JSONSchema
    /// Which keys are checked.
    public let mode: Mode
    
    /// A validator for a schema.
    ///
    /// - Parameters:
    ///   - data: The schema's JSON text: Mac Monitor's (``TelemetrySchema/data()``) or a user's.
    ///   - mode: Which keys are checked.
    /// - Throws: A ``TelemetrySchemaError`` if the schema isn't JSON or uses anything outside the supported subset.
    public init(schema data: Data, mode: Mode = .macMonitor) throws {
        schema = try JSONSchema(data: data)
        self.mode = mode
    }
    
    /// A validator for the telemetry schema the framework bundles.
    ///
    /// - Parameter mode: Which keys are checked.
    /// - Returns: The validator.
    /// - Throws: ``TelemetrySchemaError/missingResource``, or the error reading or compiling the schema.
    public static func bundled(mode: Mode = .macMonitor) throws -> TelemetryValidator {
        try TelemetryValidator(schema: try TelemetrySchema.data(), mode: mode)
    }
    
    /// The telemetry version the schema describes: its `telemetry_version` constant, if it has one.
    public var schemaVersion: String? {
        let constant = schema.root.properties[TelemetrySchema.versionKey]?.constant
        guard case .string(let version)? = constant else { return nil }
        return version
    }
    
    // MARK: Records
    
    /// The issues of one record.
    ///
    /// - Parameter json: The record's JSON text.
    /// - Returns: Its issues, empty if it's valid.
    public func issues(inRecord json: Data) -> [TelemetryIssue] {
        check(json, line: nil).issues.kept
    }
    
    /// The issues of one parsed record.
    ///
    /// - Parameters:
    ///   - record: The record, as `JSONSerialization` parsed it.
    ///   - line: The line it starts on in its trace.
    ///   - coverage: Records what the check exercises, for the tests.
    /// - Returns: Its issues, empty if it's valid.
    func issues(in record: Any, line: Int? = nil, coverage: CoverageRecorder? = nil) -> [TelemetryIssue] {
        issues(in: record, line: line, coverage: coverage, keeping: .max).kept
    }
    
    /// The issues of one parsed record, keeping some in full and counting the rest.
    ///
    /// - Parameters:
    ///   - record: The record, as `JSONSerialization` parsed it.
    ///   - line: The line it starts on in its trace.
    ///   - coverage: Records what the check exercises, for the tests.
    ///   - limit: The most issues kept in full.
    /// - Returns: Its issues.
    private func issues(in record: Any, line: Int?, coverage: CoverageRecorder?, keeping limit: Int) -> FoundIssues {
        var issues = FoundIssues(limit: limit)
        let context = CheckContext(line: line, mode: mode, coverage: coverage)
        _ = schema.check(record, against: schema.root, at: .root, in: context, into: &issues)
        return issues
    }
    
    /// What checking one record of a trace found.
    struct RecordCheck {
        /// Its issues.
        var issues = FoundIssues()
        /// Its telemetry version, if it names one.
        var version: String?
        /// Does it have Mac Monitor's own fields: a telemetry version or an event name?
        var hasMacMonitorFields = false
        /// Does it have eslogger's envelope: its numeric `schema_version` and `event_type`, and an `event` object?
        var hasESLoggerFields = false
        /// Was it cut short, or not JSON?
        var malformed = false
    }
    
    /// Check one record of a trace.
    ///
    /// - Parameters:
    ///   - json: The record's JSON text.
    ///   - line: The line it starts on, or `nil` for a record on its own.
    ///   - limit: The most issues kept in full; the rest are counted.
    /// - Returns: What the check found.
    func check(_ json: Data, line: Int?, keeping limit: Int = .max) -> RecordCheck {
        let record: Any
        do {
            record = try JSONSerialization.jsonObject(with: json)
        } catch {
            var issues = FoundIssues()
            issues.add(Self.notJSON(error, in: json, line: line))
            return RecordCheck(issues: issues, malformed: true)
        }
        let object = record as? NSDictionary
        let version = object?[TelemetrySchema.versionKey]
        let envelope = object?["schema_version"] is NSNumber && object?["event_type"] is NSNumber
            && object?["event"] is NSDictionary
        return RecordCheck(issues: issues(in: record, line: line, coverage: nil, keeping: limit),
                           version: version as? String,
                           hasMacMonitorFields: version != nil || object?["es_event_type"] != nil,
                           hasESLoggerFields: envelope)
    }
    
    /// The issue of a record that isn't JSON. In a trace, it's on the line where reading the record stopped, and its
    /// reason leaves out the place the parser names (`around line 3, column 7`), which counts from the record's first
    /// line: the same mistake in many records is one kind of issue.
    ///
    /// - Parameters:
    ///   - error: `JSONSerialization`'s error.
    ///   - json: The record's JSON text.
    ///   - line: The line the record starts on, or `nil` for a record on its own, whose reason is kept whole.
    /// - Returns: The issue.
    static func notJSON(_ error: Error, in json: Data, line: Int?) -> TelemetryIssue {
        let info = (error as NSError).userInfo
        var reason = info["NSDebugDescription"] as? String ?? "unreadable", stopped = line
        if let line {
            reason = reason.replacingOccurrences(of: #"\s+around (line \d+, column \d+|character \d+)\.?$"#, with: "",
                                                 options: .regularExpression)
            if let index = info["NSJSONSerializationErrorIndex"] as? Int {
                stopped = line + json.prefix(index).reduce(0) { $1 == UInt8(ascii: "\n") ? $0 + 1 : $0 }
            }
        }
        return TelemetryIssue(line: stopped, path: .root, schemaLocation: "#", problem: .notJSON(reason))
    }
    
    // MARK: Traces
    
    /// Check every record of a trace, reading the file a chunk at a time and checking a batch of records at a time in
    /// parallel, so memory stays flat whatever the file's size. A record's issues past those kept are only counted.
    ///
    /// Takes what ``TraceImporter`` reads: JSON Lines, pretty-printed records joined by newlines, and JSON arrays.
    /// The trace must be a regular file: pipes and standard input aren't read.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - limit: The most issues the report keeps. Every issue is counted, and passed to `onIssue` but for a record's
    ///     past ``minIssuesKeptPerRecord`` (or `limit`, if it's larger), which are only counted.
    ///   - isCancelled: Asked before each record: `true` stops checking, and the report says it stopped early.
    ///   - progress: Called after each batch, and once at the end, with the bytes read and the file's size.
    ///   - onIssue: Called with each issue kept, in file order, as each batch is checked.
    /// - Returns: The report.
    /// - Throws: ``TraceImporter/Failure/notAFile`` for a folder, pipe or device, or the error opening or reading the
    ///   file.
    public func validate(traceAt url: URL, keepingIssues limit: Int = 100,
                         isCancelled: @escaping () -> Bool = { false },
                         progress: ((_ bytesRead: Int64, _ totalBytes: Int64) -> Void)? = nil,
                         onIssue: ((TelemetryIssue) -> Void)? = nil) throws -> TelemetryValidation {
        try validate(try TraceRecordReader(url: url), keepingIssues: limit, batchSize: Self.batchSize,
                     isCancelled: isCancelled, progress: progress, onIssue: onIssue)
    }
    
    /// Check every record a reader reads (see ``validate(traceAt:keepingIssues:isCancelled:progress:onIssue:)``).
    ///
    /// - Parameters:
    ///   - reader: The trace's reader.
    ///   - limit: The most issues the report keeps.
    ///   - batchSize: The most records checked at a time.
    ///   - isCancelled: Asked before each record.
    ///   - progress: Called after each batch, and once at the end.
    ///   - onIssue: Called with each issue, in file order.
    /// - Returns: The report.
    /// - Throws: The error reading the file.
    func validate(_ reader: TraceRecordReader, keepingIssues limit: Int, batchSize: Int, isCancelled: () -> Bool,
                  progress: ((Int64, Int64) -> Void)?,
                  onIssue: ((TelemetryIssue) -> Void)?) throws -> TelemetryValidation {
        var report = TelemetryValidation(schemaVersion: schemaVersion, mode: mode, issueLimit: limit)
        var batch: [TraceRecordReader.Record] = [], bytes = 0
        let kept = max(limit, Self.minIssuesKeptPerRecord)
        /// Check the batch and add it to the report, in file order.
        func flush() {
            for result in check(batch, keeping: kept) { report.add(result, onIssue: onIssue) }
            batch.removeAll(keepingCapacity: true)
            bytes = 0
            progress?(reader.bytesRead, reader.totalBytes)
        }
        while true {
            guard !isCancelled() else {
                report.stoppedEarly = true
                break
            }
            guard let record = try reader.next() else { break }
            batch.append(record)
            if case .object(let json, _) = record { bytes += json.count }
            if batch.count >= batchSize || bytes >= Self.batchBytes { flush() }
        }
        flush()
        return report
    }
    
    /// Check a batch of records, in parallel, keeping their order.
    ///
    /// - Parameters:
    ///   - records: The records, and the malformed text between them.
    ///   - limit: The most issues of each record kept in full.
    /// - Returns: What checking each one found.
    private func check(_ records: [TraceRecordReader.Record], keeping limit: Int) -> [RecordCheck] {
        var results = [RecordCheck](repeating: RecordCheck(), count: records.count)
        results.withUnsafeMutableBufferPointer { buffer in
            let slots = buffer
            DispatchQueue.concurrentPerform(iterations: records.count) { index in
                slots[index] = autoreleasepool {
                    switch records[index] {
                    case .object(let json, let line):
                        return check(json, line: line, keeping: limit)
                    case .malformed(let line):
                        var issues = FoundIssues()
                        issues.add(line: line, path: .root, schemaLocation: "#", problem: .malformedRecord)
                        return RecordCheck(issues: issues, malformed: true)
                    }
                }
            }
        }
        return results
    }
}
