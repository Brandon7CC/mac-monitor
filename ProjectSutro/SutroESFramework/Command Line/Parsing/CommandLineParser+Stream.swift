//
//  CommandLineParser+Stream.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import EndpointSecurity


// MARK: - Streams
extension CommandLineParser {
    /// `stream [EVENT...] [--format text|jsonl|pretty] [--json] [--pretty] [--text] [--no-mutes] [--include-self]
    /// [--yara-scan] [--no-url-paths] [--every EVENT] [--for DURATION] [--count N] [--pid PID]
    /// [--process|--signing-id|--target|--grep REGEX] [--predicate PREDICATE] [--indicator NAME|ID]`.
    ///
    /// `--json`, `--pretty` and `--text` are short for `--format jsonl|pretty|text`. Each filter option may be given
    /// more than once (``StreamFilter``), and so may `--every`.
    ///
    /// - Parameter cursor: The arguments.
    /// - Returns: The stream asked for.
    /// - Throws: ``CommandLineUsageError`` for an event that can't be streamed, a bad format, two formats, a bad
    ///   duration, count, process ID, regular expression or predicate, an `--every` event with no field filter, or an
    ///   unknown option.
    static func stream(_ cursor: inout ArgumentCursor) throws -> StreamInvocation {
        var invocation = StreamInvocation(), seen = Set<UInt32>()
        while let argument = cursor.next() {
            switch argument {
            case .positional(let name):
                let events = name == "all" ? StreamPlan.streamableEvents : [try event(named: name)]
                invocation.events += events.filter { seen.insert($0.rawValue).inserted }
            case .option("--format", let attached):
                let value = try cursor.value(of: "--format", attached: attached, command: "stream")
                guard let format = StreamOutputFormat(rawValue: value) else {
                    let names = StreamOutputFormat.allCases.map(\.rawValue)
                    throw CommandLineUsageError("--format must be \(names.dropLast().joined(separator: ", ")) or "
                                                + "\(names.last ?? ""), not '\(value)'.", command: "stream")
                }
                try choose(format, for: &invocation)
            case .option(let option, nil) where formatShorthands[option] != nil:
                try choose(formatShorthands[option]!, for: &invocation)
            case .option("--no-mutes", nil):
                invocation.appliesSavedMutes = false
            case .option("--include-self", nil):
                invocation.includeSelf = true
            case .option("--yara-scan", nil):
                invocation.scansWrittenFiles = true
            case .option("--no-url-paths", nil):
                invocation.recordsURLPaths = false
            case .option("--every", let attached):
                try every(cursor.value(of: "--every", attached: attached, command: "stream"), in: &invocation)
            case .option("--for", let attached):
                invocation.duration = try duration(cursor.value(of: "--for", attached: attached, command: "stream"))
            case .option("--count", let attached):
                let value = try cursor.value(of: "--count", attached: attached, command: "stream")
                guard let count = Int(value), count > 0 else {
                    throw CommandLineUsageError("--count must be a whole number above 0, not '\(value)'.",
                                                command: "stream")
                }
                invocation.limit = count
            case .option("--pid", let attached):
                let value = try cursor.value(of: "--pid", attached: attached, command: "stream")
                guard let pid = Int32(value), pid >= 0 else {
                    throw CommandLineUsageError("--pid needs a process ID, not '\(value)'.", command: "stream")
                }
                invocation.filter.pids.append(pid)
            case .option(let option, let attached) where patternOptions[option] != nil:
                let pattern = try StreamFilter.Pattern(cursor.value(of: option, attached: attached, command: "stream"),
                                                       option: option)
                invocation.filter[keyPath: patternOptions[option]!].append(pattern)
            case .option("--predicate", let attached):
                let value = try cursor.value(of: "--predicate", attached: attached, command: "stream")
                invocation.filter.predicates.append(try StreamFilter.Predicate(value))
            case .option("--indicator", let attached):
                let value = try cursor.value(of: "--indicator", attached: attached, command: "stream")
                    .trimmingCharacters(in: .whitespaces)
                guard !value.isEmpty else {
                    throw CommandLineUsageError("--indicator needs an indicator's name.", command: "stream")
                }
                invocation.filter.indicators.append(value)
            case .option(let option, .some) where flags.contains(option):
                throw CommandLineUsageError("\(option) takes no value.", command: "stream")
            case .option(let option, _):
                throw unknownOption(option, for: "stream", among: CommandLineOption.stream)
            }
        }
        return invocation
    }
    
    static let formatShorthands: [String: StreamOutputFormat] = ["--json": .jsonl, "--pretty": .pretty, "--text": .text]
    static let flags = Set(formatShorthands.keys).union(["--no-mutes", "--include-self", "--yara-scan",
                                                         "--no-url-paths"])
    /// The filter options that take a regular expression, and where each keeps them.
    static let patternOptions: [String: WritableKeyPath<StreamFilter, [StreamFilter.Pattern]>] = [
        "--process": \.processes, "--signing-id": \.signingIDs, "--target": \.targets, "--grep": \.greps
    ]
    
    /// The units `--for` takes, longest first so `ms` isn't read as `m`.
    static let durationUnits: [(suffix: String, seconds: TimeInterval)] = [("ms", 0.001), ("s", 1), ("m", 60),
                                                                          ("h", 3_600)]
    /// The longest `--for`: a year, in seconds.
    static let longestDuration: TimeInterval = 365 * 24 * 3_600
    
    /// A `--for` value in seconds.
    ///
    /// - Parameter value: A number of seconds, or a number with a unit: 500ms, 30s, 5m, 1.5h.
    /// - Returns: The seconds.
    /// - Throws: ``CommandLineUsageError`` for anything else, a time that isn't above 0, or one over a year.
    static func duration(_ value: String) throws -> TimeInterval {
        let unit = durationUnits.first { value.hasSuffix($0.suffix) }
        guard let amount = Double(value.dropLast(unit?.suffix.count ?? 0)), amount.isFinite, amount > 0 else {
            throw CommandLineUsageError("--for must be a time such as 30s, 5m or 1h, not '\(value)'.",
                                        command: "stream")
        }
        let seconds = amount * (unit?.seconds ?? 1)
        guard seconds <= longestDuration else {
            throw CommandLineUsageError("--for can be at most a year (8760h), not '\(value)'.", command: "stream")
        }
        return seconds
    }
    
    /// Set the format, refusing a second, different one.
    ///
    /// - Parameters:
    ///   - format: The format.
    ///   - invocation: The stream.
    /// - Throws: ``CommandLineUsageError`` for two formats.
    private static func choose(_ format: StreamOutputFormat, for invocation: inout StreamInvocation) throws {
        if let chosen = invocation.format, chosen != format {
            throw CommandLineUsageError("Choose one output format, not both \(chosen.rawValue) and \(format.rawValue).",
                                        command: "stream")
        }
        invocation.format = format
    }
}
