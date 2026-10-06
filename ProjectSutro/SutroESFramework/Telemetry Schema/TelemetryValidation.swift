//
//  TelemetryValidation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Validation report
/// What checking a trace against a telemetry schema found, worded the same in the app and on the command line.
public struct TelemetryValidation: Sendable {
    /// The most kinds of issue counted apart: past them, issues of new kinds are only counted in ``issueTotal``, so a
    /// file can't grow the report without bound.
    public static let maxIssueKinds = 1_000
    /// The most telemetry versions kept.
    public static let maxVersions = 16
    /// The advice a hint gives for eslogger's own JSON when the front end names no control of its own.
    public static let esloggerAdvice = "Check only the keys eslogger writes, in eslogger mode."
    
    /// The telemetry version of the schema the trace was checked against.
    public let schemaVersion: String?
    /// Which keys were checked.
    public let mode: TelemetryValidator.Mode
    /// The most issues ``issues`` keeps.
    public let issueLimit: Int
    
    /// Records read: valid, invalid, and malformed.
    public internal(set) var records = 0
    /// Records without issues.
    public internal(set) var valid = 0
    /// Records with issues.
    public internal(set) var invalid = 0
    /// Records cut short, and text that isn't a record.
    public internal(set) var malformed = 0
    /// The first ``issueLimit`` issues, in file order.
    public internal(set) var issues: [TelemetryIssue] = []
    /// Every issue found.
    public internal(set) var issueTotal = 0
    /// How many issues there are of each kind (the first ``maxIssueKinds`` kinds): one change to the export across
    /// 10,000 records is one kind.
    public internal(set) var issueCounts: [TelemetryIssue.Kind: Int] = [:]
    /// The telemetry versions the records name (the first ``maxVersions``), each cut by ``JSONText/cut(_:)``.
    public internal(set) var telemetryVersions: Set<String> = []
    /// Did checking stop before the end of the file?
    public internal(set) var stoppedEarly = false
    /// Records that are eslogger's own JSON: eslogger's envelope without Mac Monitor's fields (no telemetry version
    /// and no event name).
    var esloggerRecords = 0
    /// Records with Mac Monitor's fields but no telemetry version: exported before Mac Monitor 2.2.0.
    var unversionedRecords = 0
    
    /// Is there a record, is every record valid, and was every record checked? A file with no records isn't a valid
    /// trace: an export that came out empty, or a trace emptied by mistake, must not pass.
    public var isValid: Bool { records > 0 && invalid == 0 && malformed == 0 && !stoppedEarly }
    
    /// Does the trace look like eslogger's own JSON: does every record that's JSON have eslogger's envelope (its
    /// numeric `schema_version` and `event_type`, and an `event` object) without Mac Monitor's fields (no telemetry
    /// version and no event name)? Never in ``TelemetryValidator/Mode/eslogger`` mode, which checks it as eslogger's
    /// already.
    public var looksLikeESLogger: Bool {
        mode == .macMonitor && records > malformed && esloggerRecords == records - malformed
    }
    
    /// - Parameters:
    ///   - schemaVersion: The telemetry version of the schema.
    ///   - mode: Which keys are checked.
    ///   - issueLimit: The most issues to keep.
    init(schemaVersion: String?, mode: TelemetryValidator.Mode, issueLimit: Int) {
        self.schemaVersion = schemaVersion
        self.mode = mode
        self.issueLimit = issueLimit
    }
    
    /// Add a record's check.
    ///
    /// - Parameters:
    ///   - check: What checking the record found.
    ///   - onIssue: Called with each of its issues kept in full.
    mutating func add(_ check: TelemetryValidator.RecordCheck, onIssue: ((TelemetryIssue) -> Void)?) {
        records += 1
        if check.malformed { malformed += 1 } else if check.issues.count == 0 { valid += 1 } else { invalid += 1 }
        if !check.malformed && check.hasESLoggerFields && !check.hasMacMonitorFields { esloggerRecords += 1 }
        if !check.malformed && check.hasMacMonitorFields && check.version == nil { unversionedRecords += 1 }
        if let version = check.version, telemetryVersions.count < Self.maxVersions {
            telemetryVersions.insert(JSONText.cut(version))
        }
        for issue in check.issues.kept {
            if issues.count < issueLimit { issues.append(issue) }
            tally(issue.kind, 1)
            onIssue?(issue)
        }
        for (kind, count) in check.issues.dropped { tally(kind, count) }
        issueTotal += check.issues.count
    }
    
    /// Count issues of a kind, if it's one of the first ``maxIssueKinds`` kinds.
    ///
    /// - Parameters:
    ///   - kind: The kind.
    ///   - count: How many issues of it there are.
    private mutating func tally(_ kind: TelemetryIssue.Kind, _ count: Int) {
        guard issueCounts[kind] != nil || issueCounts.count < Self.maxIssueKinds else { return }
        issueCounts[kind, default: 0] += count
    }
    
    // MARK: Text
    
    /// The schema checked against, in words: `Mac Monitor telemetry 1.0.0`.
    private var schemaName: String {
        let name = "Mac Monitor telemetry" + (schemaVersion.map { " \($0)" } ?? "")
        return mode == .eslogger ? "eslogger's fields of \(name)" : name
    }
    
    /// One line on the whole trace: `trace.jsonl: 10,884 records, all valid (Mac Monitor telemetry 1.0.0).`
    ///
    /// - Parameter fileName: The trace's name.
    /// - Returns: The line.
    public func summary(fileName: String) -> String {
        let counts: String
        if records == 0 {
            counts = "no records"
        } else if valid == records {
            counts = "\(Self.count(records, "record")), all valid"
        } else {
            let parts = [(valid, "valid"), (invalid, "invalid"), (malformed, "malformed")].filter { $0.0 > 0 }
            let tally = parts.map { "\(Self.grouped($0)) \($1)" }.joined(separator: ", ")
            counts = "\(Self.count(records, "record")): \(tally); \(Self.count(issueTotal, "issue"))"
        }
        return "\(fileName): \(counts) (\(schemaName))." + (stoppedEarly ? " Stopped before the end of the file." : "")
    }
    
    /// Advice when the trace isn't what the schema describes: eslogger's own JSON, an export from before telemetry
    /// versions, or another telemetry version.
    ///
    /// - Parameter esloggerAdvice: How to check only eslogger's keys, as a sentence ending the hint for eslogger's own
    ///   JSON: the app names its button, and the command line its option.
    /// - Returns: The hint, or `nil` if the trace is what the schema describes.
    public func hint(esloggerAdvice: String = TelemetryValidation.esloggerAdvice) -> String? {
        if looksLikeESLogger {
            return "This looks like eslogger's JSON, without Mac Monitor's fields. \(esloggerAdvice)"
        }
        if telemetryVersions.isEmpty && unversionedRecords > 0 {
            return "No record names a telemetry version: this looks like an export from before Mac Monitor 2.2.0, "
                + "which no schema describes. Open it in Mac Monitor with File > Open Trace… and export it again "
                + "to check it."
        }
        let others = telemetryVersions.filter { $0 != schemaVersion }.sorted().map(JSONText.quoted)
        guard !others.isEmpty else { return nil }
        return "This trace is telemetry \(others.joined(separator: ", ")); validate it with the schema attached to the "
            + "release that wrote it."
    }
    
    /// The kinds of issue, most frequent first.
    public var sortedIssueCounts: [(kind: TelemetryIssue.Kind, count: Int)] {
        issueCounts.map { (kind: $0.key, count: $0.value) }
            .sorted { ($1.count, $0.kind.description) < ($0.count, $1.kind.description) }
    }
    
    /// The whole report as text: the summary, the hint, the kinds of issue with their counts, and the issues kept.
    ///
    /// - Parameters:
    ///   - fileName: The trace's name.
    ///   - esloggerAdvice: How to check only eslogger's keys, for the hint (see ``hint(esloggerAdvice:)``).
    /// - Returns: The report.
    public func report(fileName: String, esloggerAdvice: String = TelemetryValidation.esloggerAdvice) -> String {
        let head = [summary(fileName: fileName), hint(esloggerAdvice: esloggerAdvice)].compactMap { $0 }
            .joined(separator: "\n")
        return details.isEmpty ? head : "\(head)\n\n\(details)"
    }
    
    /// The report below its summary and hint: the kinds of issue with their counts, then the issues kept. Empty when
    /// there are no issues. The app shows it under its own heading.
    public var details: String {
        var sections: [[String]] = []
        if !issueCounts.isEmpty {
            sections.append(["Issues by kind:"] + sortedIssueCounts.map { "  \(Self.grouped($0.count)) x \($0.kind)" })
        }
        if !issues.isEmpty {
            let some = "First \(issues.count) of \(Self.grouped(issueTotal)) issues:"
            sections.append([issues.count < issueTotal ? some : "Issues:"] + issues.map { "  \($0)" })
        }
        return sections.map { $0.joined(separator: "\n") }.joined(separator: "\n\n")
    }
    
    /// A count and its noun: `1 record`, `10,884 records`.
    ///
    /// - Parameters:
    ///   - value: The count.
    ///   - noun: The noun, singular.
    /// - Returns: The text.
    private static func count(_ value: Int, _ noun: String) -> String {
        "\(grouped(value)) \(noun)\(value == 1 ? "" : "s")"
    }
    
    /// A count with its thousands separated by commas, whatever the locale, so the app, the command line and the
    /// tests read the same: `10,884`.
    ///
    /// - Parameter value: The count.
    /// - Returns: The digits.
    static func grouped(_ value: Int) -> String {
        var digits = String(value.magnitude), groups: [Substring] = []
        while digits.count > 3 {
            groups.insert(Substring(digits.suffix(3)), at: 0)
            digits.removeLast(3)
        }
        return (value < 0 ? "-" : "") + ([Substring(digits)] + groups).joined(separator: ",")
    }
}
