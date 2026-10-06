//
//  ValidateCommand.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Validate command
/// `macmonitor validate [--eslogger] TRACE` (command line context): check a trace against the telemetry schema the
/// framework bundles, with the ``TelemetryValidator`` and the report Help > Telemetry Schema… uses, and write the
/// report to standard output. Needs neither root nor the Security Extension.
///
/// The trace must be a regular file: the validator measures it and reads it a chunk at a time, and a pipe or a device
/// could block forever. So standard input (`-`), a folder, a pipe or a device can't be read (66), as a missing or
/// unreadable file can't. A trace with no records isn't valid (65).
public struct ValidateCommand {
    /// How a check ended.
    public enum Outcome: Equatable {
        /// The trace has records, and every one follows the schema.
        case valid
        /// A record doesn't follow the schema or isn't JSON, or the trace has none: the report says which, and where.
        case invalid
        /// Checking stopped before the end of the trace, as asked: the report says so.
        case stopped
        /// The trace couldn't be checked, or the report couldn't be written.
        case failed(CommandLineFailure)
        
        /// How `macmonitor` exits: 0 when valid, 65 when invalid, or the failure's status. `nil` for a check that
        /// stopped, which exits by the signal that stopped it.
        public var exit: CommandLineExit? {
            switch self {
            case .valid: return .success
            case .invalid: return .dataError
            case .stopped: return nil
            case .failed(let failure): return failure.exit
            }
        }
    }
    
    /// The most issues a report lists, as in the app; every issue is counted.
    public static let issueLimit = 100
    /// How the report's hint for eslogger's own JSON says to check only eslogger's keys.
    public static let esloggerAdvice = "Add --eslogger to check only the keys eslogger writes."
    
    private let output: StreamOutput
    /// Asked before each record: `true` stops checking.
    private let isCancelled: () -> Bool
    /// Reads the schema.
    private let schema: () throws -> Data
    
    /// - Parameters:
    ///   - output: Standard output.
    ///   - isCancelled: Asked before each record: `true` stops checking, as a signal does in `macmonitor`.
    ///   - schema: Reads the schema: the framework's (``TelemetrySchema/data()``), unless a test passes its own.
    public init(output: StreamOutput, isCancelled: @escaping () -> Bool = { false },
                schema: @escaping () throws -> Data = TelemetrySchema.data) {
        self.output = output
        self.isCancelled = isCancelled
        self.schema = schema
    }
    
    /// Check a trace and write the report, even when checking stopped early.
    ///
    /// - Parameter invocation: The trace, and which of its keys to check.
    /// - Returns: How the check ended.
    public func run(_ invocation: ValidateInvocation) -> Outcome {
        guard invocation.path != "-" else {
            return .failed(CommandLineFailure(.noInput, """
                validate reads a trace from a file, not standard input. Save it to a file, then validate that.
                """))
        }
        /// `URL(fileURLWithPath: "")` is the current folder, but an empty path names no file: `open("")`, and so
        /// `mute import ""`, fail with ENOENT.
        guard !invocation.path.isEmpty else {
            return .failed(.unreadable(TerminalSafeText.quoted(""), because: POSIXError(.ENOENT)))
        }
        let validator: TelemetryValidator
        do {
            validator = try TelemetryValidator(schema: try schema(), mode: invocation.mode)
        } catch {
            return .failed(.schema(error))
        }
        let report: TelemetryValidation
        do {
            report = try validator.validate(traceAt: URL(fileURLWithPath: invocation.path),
                                            keepingIssues: Self.issueLimit, isCancelled: isCancelled)
        } catch {
            return .failed(.unreadable(TerminalSafeText.quoted(invocation.path), because: error))
        }
        if case .failure(let failure) = output.writeResult(Data(Self.text(of: report, path: invocation.path).utf8)) {
            return .failed(failure)
        }
        if report.stoppedEarly { return .stopped }
        return report.isValid ? .valid : .invalid
    }
    
    /// The report as `macmonitor` writes it: named by the path as typed, with the hint naming `--eslogger`, and safe
    /// for a terminal, since the path and a trace's values, keys, event names and versions are anyone's text.
    ///
    /// The path is escaped before it goes in, and the report writes a trace's text as identifiers or JSON strings, so
    /// a newline in either stays `\n` and can't start a line of its own. Each line is then escaped for what JSON
    /// leaves alone: DEL, C1 and the bidirectional controls.
    ///
    /// - Parameters:
    ///   - report: The report.
    ///   - path: The trace, as typed.
    /// - Returns: The text, ending in a newline.
    static func text(of report: TelemetryValidation, path: String) -> String {
        report.report(fileName: TerminalSafeText.text(path), esloggerAdvice: esloggerAdvice)
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { TerminalSafeText.text(String($0)) }
            .joined(separator: "\n") + "\n"
    }
}
