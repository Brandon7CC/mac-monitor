//
//  TelemetryIssue.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Issues
/// One way a record differs from Mac Monitor's telemetry schema, worded the same in the app and on the command line:
/// `line 812: event.exec.target.cdhash: "0df5…" doesn't match ^[0-9A-F]{40}$`.
public struct TelemetryIssue: Error, Hashable, Sendable, CustomStringConvertible {
    /// What's wrong.
    public enum Problem: Hashable, Sendable {
        /// A key the schema requires is missing.
        case missing
        /// A key the schema doesn't have.
        case unexpected
        /// An event of a type Mac Monitor doesn't record, by eslogger's name for it (cut by ``JSONText/cut(_:)``).
        case unsupportedEvent(String)
        /// A value of the wrong JSON type: the types allowed, and the type found.
        case type(expected: [String], found: String)
        /// A value other than the one the schema allows, which it names as JSON.
        case notConst(String)
        /// A value that isn't one of the schema's.
        case notInEnum
        /// A string that doesn't match the schema's pattern.
        case pattern(String)
        /// An object with too few or too many keys: how many it has, and the bounds.
        case propertyCount(found: Int, minimum: Int?, maximum: Int?)
        /// A value that matches none of the schema's alternatives: the JSON types they allow, and the type found.
        case noBranch(expected: [String], found: String)
        /// One of Mac Monitor's own fields, in a record checked as eslogger's.
        case macMonitorFieldInESLogger
        /// A record cut short, or text that isn't a record.
        case malformedRecord
        /// A record that isn't JSON: why.
        case notJSON(String)
    }
    
    /// A kind of issue, for counting: its path with every index generalized to `[]`, and its problem without the value.
    public struct Kind: Hashable, Sendable, CustomStringConvertible {
        /// The path: `event.exec.args[]`.
        public let path: String
        /// The problem: `doesn't match ^[0-9A-F]{40}$`.
        public let problem: String
        /// `event.exec.args[]: missing`, or the problem alone for an issue with the whole record.
        public var description: String { path.isEmpty ? problem : "\(path): \(problem)" }
        
        /// - Parameters:
        ///   - path: The path, with every index generalized.
        ///   - problem: The problem, without the value.
        init(path: String, problem: String) {
            self.path = path
            self.problem = problem
        }
        
        /// The kind of an issue that isn't made: one a record has past the issues it keeps.
        ///
        /// - Parameters:
        ///   - path: Where the value is in the record.
        ///   - problem: What's wrong.
        init(path: InstancePath, problem: Problem) {
            self.init(path: path.generalized, problem: TelemetryIssue.text(of: problem, value: nil))
        }
    }
    
    /// The line the record starts on in its trace, from 1 (for a record that isn't JSON, the line where reading it
    /// stopped), or `nil` for a record checked on its own.
    public let line: Int?
    /// Where the value is in the record: `event.exec.target.cdhash`, or `""` for the whole record.
    public let path: String
    /// ``path`` with every index generalized to `[]`.
    public let generalPath: String
    /// The schema location the value was checked against, as a JSON pointer.
    public let schemaLocation: String
    /// What's wrong.
    public let problem: Problem
    /// The value, as the issue shows it (see ``JSONText/describe(_:)``), when the problem is with its value.
    public let value: String?
    
    /// The issue's kind, for counting issues of the same kind.
    public var kind: Kind { Kind(path: generalPath, problem: Self.text(of: problem, value: nil)) }
    
    /// The issue, as a line: its line number, path and problem.
    public var description: String {
        let place = [line.map { "line \($0)" }, path.isEmpty ? nil : path].compactMap { $0 }.joined(separator: ": ")
        let text = Self.text(of: problem, value: value)
        return place.isEmpty ? text : "\(place): \(text)"
    }
    
    /// A problem as words.
    ///
    /// - Parameters:
    ///   - problem: The problem.
    ///   - value: The value to show, or `nil` for none, as a ``Kind`` shows it.
    /// - Returns: The problem: `"0df5…" doesn't match ^[0-9A-F]{40}$`.
    private static func text(of problem: Problem, value: String?) -> String {
        let shown = value.map { "\($0) " } ?? ""
        switch problem {
        case .missing:
            return "missing"
        case .unexpected:
            return "not in the schema"
        case .unsupportedEvent(let name):
            return "Mac Monitor doesn't record \(InstancePath.name(name)) events"
        case .type(let expected, let found), .noBranch(let expected, let found):
            return "expected \(expected.joined(separator: " or ")), found \(value ?? found)"
        case .notConst(let expected):
            return "\(shown)isn't \(expected)"
        case .notInEnum:
            return "\(shown)isn't one of the schema's values"
        case .pattern(let pattern):
            return "\(shown)doesn't match \(pattern)"
        case .propertyCount(let found, let minimum, let maximum):
            let bound = switch (minimum, maximum) {
            case let (low?, high?) where low == high: "\(low)"
            case let (low?, high?): "\(low) to \(high)"
            case let (low?, nil): "at least \(low)"
            default: "at most \(maximum ?? 0)"
            }
            return "has \(found) \(found == 1 ? "key" : "keys"), expected \(bound)"
        case .macMonitorFieldInESLogger:
            return "Mac Monitor field in an eslogger record"
        case .malformedRecord:
            return "incomplete or malformed JSON"
        case .notJSON(let reason):
            return "not JSON (\(reason))"
        }
    }
    
    /// - Parameters:
    ///   - line: The line the record starts on, or `nil` for a record checked on its own.
    ///   - path: Where the value is in the record.
    ///   - schemaLocation: The schema location the value was checked against.
    ///   - problem: What's wrong.
    ///   - value: The value, when the problem is with its value.
    init(line: Int?, path: InstancePath, schemaLocation: String, problem: Problem, value: Any? = nil) {
        self.line = line
        self.path = path.rendered
        generalPath = path.generalized
        self.schemaLocation = schemaLocation
        self.problem = problem
        self.value = value.map(JSONText.describe)
    }
}


// MARK: - Paths
/// Where a value is in a record, built as the check reads into it and rendered only when an issue names it.
indirect enum InstancePath: Equatable {
    /// The record itself.
    case root
    /// A key of an object.
    case key(InstancePath, String)
    /// An element of an array.
    case index(InstancePath, Int)
    
    /// The path as text: `event.exec.args[2]`; a key that isn't a short identifier is written `["key"]`.
    var rendered: String { render(generalized: false) }
    /// The path as text with every index generalized: `event.exec.args[]`.
    var generalized: String { render(generalized: true) }
    
    /// The path as text.
    ///
    /// - Parameter generalized: Write every index as `[]`.
    /// - Returns: The text.
    private func render(generalized: Bool) -> String {
        switch self {
        case .root:
            return ""
        case .key(let parent, let key):
            let prefix = parent.render(generalized: generalized)
            guard Self.isIdentifier(key) else { return "\(prefix)[\(JSONText.quoted(key))]" }
            return prefix.isEmpty ? key : "\(prefix).\(key)"
        case .index(let parent, let index):
            return "\(parent.render(generalized: generalized))[\(generalized ? "" : "\(index)")]"
        }
    }
    
    /// A key as an issue names it on its own, such as an event's name: as a path writes it after a dot, or else
    /// quoted, so a key of any length or with any characters stays short and on one line.
    ///
    /// - Parameter key: The key.
    /// - Returns: `exec`, or `"od attribute"`.
    static func name(_ key: String) -> String {
        isIdentifier(key) ? key : JSONText.quoted(key)
    }
    
    /// Can a key be written after a dot: at most ``JSONText/maxQuoted`` ASCII letters, digits and underscores, not
    /// starting with a digit? A longer key is quoted, which cuts it.
    ///
    /// Tested on the key's bytes: `CharacterSet` shares one reference-counted storage between threads, which made
    /// checking in parallel slower than checking on one thread.
    ///
    /// - Parameter key: The key.
    /// - Returns: `true` if it can.
    private static func isIdentifier(_ key: String) -> Bool {
        let digits = UInt8(ascii: "0")...UInt8(ascii: "9"), letters = UInt8(ascii: "a")...UInt8(ascii: "z")
        guard key.utf8.count <= JSONText.maxQuoted, let first = key.utf8.first, !digits.contains(first) else {
            return false
        }
        return key.utf8.allSatisfy { $0 == UInt8(ascii: "_") || digits.contains($0) || letters.contains($0 | 0x20) }
    }
}


// MARK: - Issues found
/// The issues a check finds: the first ``limit`` in full, and past them only how many there are of each kind, so a
/// record with millions of broken values can't take gigabytes.
struct FoundIssues {
    /// The most issues kept in full.
    let limit: Int
    /// The issues kept, in the order they were found.
    private(set) var kept: [TelemetryIssue] = []
    /// How many issues past ``limit`` there are of each kind (the first ``TelemetryValidation/maxIssueKinds`` kinds).
    private(set) var dropped: [TelemetryIssue.Kind: Int] = [:]
    /// Every issue found, kept or not.
    private(set) var count = 0
    
    /// - Parameter limit: The most issues to keep in full.
    init(limit: Int = .max) {
        self.limit = limit
    }
    
    /// Add an issue, made only if it's kept.
    ///
    /// - Parameters:
    ///   - line: The line the record starts on, or `nil` for a record checked on its own.
    ///   - path: Where the value is in the record.
    ///   - schemaLocation: The schema location the value was checked against.
    ///   - problem: What's wrong.
    ///   - value: The value, when the problem is with its value.
    mutating func add(line: Int?, path: InstancePath, schemaLocation: String, problem: TelemetryIssue.Problem,
                      value: Any? = nil) {
        guard kept.count < limit else { return drop(TelemetryIssue.Kind(path: path, problem: problem), count: 1) }
        add(TelemetryIssue(line: line, path: path, schemaLocation: schemaLocation, problem: problem, value: value))
    }
    
    /// Add an issue that's made already.
    ///
    /// - Parameter issue: The issue.
    mutating func add(_ issue: TelemetryIssue) {
        guard kept.count < limit else { return drop(issue.kind, count: 1) }
        kept.append(issue)
        count += 1
    }
    
    /// Add the issues another check found, after these.
    ///
    /// - Parameter other: The other check's issues.
    mutating func add(contentsOf other: FoundIssues) {
        other.kept.forEach { add($0) }
        for (kind, count) in other.dropped { drop(kind, count: count) }
        count += other.count - other.kept.count - other.dropped.values.reduce(0, +)
    }
    
    /// Count issues past the limit.
    ///
    /// - Parameters:
    ///   - kind: Their kind.
    ///   - count: How many there are.
    private mutating func drop(_ kind: TelemetryIssue.Kind, count: Int) {
        self.count += count
        guard dropped[kind] != nil || dropped.count < TelemetryValidation.maxIssueKinds else { return }
        dropped[kind, default: 0] += count
    }
}
