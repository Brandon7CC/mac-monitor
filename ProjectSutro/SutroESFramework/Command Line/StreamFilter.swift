//
//  StreamFilter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation


// MARK: - Stream filter
/// Which events `macmonitor stream` writes: `--pid`, `--process`, `--signing-id`, `--target`, `--grep` and `--where`.
///
/// An option given more than once matches an event if any of its values does, and an event is written only if every
/// option given matches it: `--process curl --process wget --signing-id '^com\.apple\.'` writes Apple's curl and
/// wget. A pattern is a regular expression (`NSRegularExpression`), found anywhere in the value unless it's anchored,
/// and case-sensitive unless it starts with `(?i)`. `--where` is an `NSPredicate` on the event's record.
///
/// `--pid`, `--process` and `--target` read the event's header, which every format decodes. `--signing-id`, `--grep`
/// and `--where` read its export record, the line `--format jsonl` writes, so text output with one of them encodes
/// every event's record too, as JSONL output does. Events filtered out were captured and read, so they're never lost.
public struct StreamFilter: Equatable {
    /// A regular expression, as typed.
    public struct Pattern: Equatable {
        /// What was typed.
        public let source: String
        private let expression: NSRegularExpression

        /// - Parameters:
        ///   - source: The regular expression.
        ///   - option: The option it was given to, for the error.
        /// - Throws: ``CommandLineUsageError`` if it isn't a regular expression.
        public init(_ source: String, option: String) throws {
            guard let expression = try? NSRegularExpression(pattern: source) else {
                throw CommandLineUsageError("\(option) needs a regular expression, not '\(source)'.",
                                            command: "stream")
            }
            self.source = source
            self.expression = expression
        }

        /// Is the pattern found in some text?
        ///
        /// - Parameter text: The text.
        /// - Returns: `true` if it's found anywhere in it.
        public func matches(_ text: String) -> Bool {
            expression.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
        }

        /// Two patterns are the same if they were typed the same.
        public static func == (lhs: Pattern, rhs: Pattern) -> Bool {
            lhs.source == rhs.source
        }
    }

    /// An `NSPredicate`, as typed, that only compares the record's values (``PredicateGuard``).
    public struct Predicate: Equatable {
        /// What was typed.
        public let source: String
        private let predicate: NSPredicate

        /// - Parameter source: The predicate's format.
        /// - Throws: ``CommandLineUsageError`` if `NSPredicate` can't read it, or it does more than compare values.
        public init(_ source: String) throws {
            do {
                predicate = try PredicateBridge.predicate(withFormat: source)
            } catch {
                /// `NSPredicate` ends some reasons with a period and not others.
                let reason = error.localizedDescription.hasSuffix(".") ? error.localizedDescription
                    : error.localizedDescription + "."
                throw CommandLineUsageError("--where can't read '\(source)': \(reason)", command: "stream")
            }
            try PredicateGuard.check(predicate)
            self.source = source
        }

        /// Evaluate the predicate on a record.
        ///
        /// - Parameter record: The record.
        /// - Returns: Does the record match?
        /// - Throws: ``StreamFilterError`` if the predicate can't be evaluated on it, such as `MATCHES` on a number.
        func evaluate(on record: NSDictionary) throws -> Bool {
            var matches = ObjCBool(false)
            do {
                try PredicateBridge.evaluate(predicate, with: PredicateRecord(record), matches: &matches)
            } catch {
                throw StreamFilterError(predicate: source, reason: error.localizedDescription)
            }
            return matches.boolValue
        }

        /// The same predicate, parsed again, for another thread: `NSPredicate` doesn't say it's thread-safe.
        var copy: Predicate {
            (try? Predicate(source)) ?? self
        }

        /// Two predicates are the same if they were typed the same.
        public static func == (lhs: Predicate, rhs: Predicate) -> Bool {
            lhs.source == rhs.source
        }
    }

    /// `--pid`: the initiating process's ID.
    public var pids: [Int32] = []
    /// `--process`: the initiating process's executable path.
    public var processes: [Pattern] = []
    /// `--signing-id`: the initiating process's signing ID.
    public var signingIDs: [Pattern] = []
    /// `--target`: the event's target path.
    public var targets: [Pattern] = []
    /// `--grep`: any string in the event's record.
    public var greps: [Pattern] = []
    /// `--where`: the event's record.
    public var predicates: [Predicate] = []

    /// No filter: every event is written.
    public init() {}

    /// Does deciding need the event's export record?
    public var readsRecords: Bool {
        !(signingIDs.isEmpty && greps.isEmpty && predicates.isEmpty)
    }

    /// The same filter for another thread.
    var copy: StreamFilter {
        var copy = self
        copy.predicates = predicates.map(\.copy)
        return copy
    }

    /// Does an event's header pass `--pid`, `--process` and `--target`?
    ///
    /// - Parameter header: The event's header.
    /// - Returns: `true` if it does.
    public func admits(_ header: EventHeader) -> Bool {
        Self.any(pids) { $0 == header.process.pid }
            && Self.any(processes) { $0.matches(header.process.path ?? "") }
            && Self.any(targets) { $0.matches(header.targetPath ?? "") }
    }

    /// Does an event's record pass `--signing-id`, `--grep` and `--where`?
    ///
    /// - Parameter record: The event's export record.
    /// - Returns: `true` if it does.
    /// - Throws: ``StreamFilterError`` if a `--where` predicate can't be evaluated on it.
    public func admits(record: NSDictionary) throws -> Bool {
        let signingID = record.value(forKeyPath: "process.signing_id") as? String ?? ""
        guard Self.any(signingIDs, { $0.matches(signingID) }),
              Self.any(greps, { pattern in Self.containsString(record, where: pattern.matches) }) else { return false }
        guard !predicates.isEmpty else { return true }
        for predicate in predicates {
            if try predicate.evaluate(on: record) { return true }
        }
        return false
    }

    /// Does any value pass, or are there none to pass?
    ///
    /// - Parameters:
    ///   - values: An option's values.
    ///   - test: Whether a value matches.
    /// - Returns: `true` if `values` is empty or one matches.
    private static func any<Value>(_ values: [Value], _ test: (Value) -> Bool) -> Bool {
        values.isEmpty || values.contains(where: test)
    }

    /// Does a JSON value hold a string that passes, at any depth?
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - test: Whether a string matches.
    /// - Returns: `true` at the first string that matches.
    private static func containsString(_ value: Any, where test: (String) -> Bool) -> Bool {
        switch value {
        case let string as String:
            return test(string)
        case let object as NSDictionary:
            return object.allValues.contains { containsString($0, where: test) }
        case let array as NSArray:
            return array.contains { containsString($0, where: test) }
        default:
            return false
        }
    }
}


/// A `--where` predicate that can't be evaluated on an event, which isn't written.
public struct StreamFilterError: Error, Equatable, CustomStringConvertible {
    /// The predicate, as typed.
    public let predicate: String
    /// Why, as `NSPredicate` says.
    public let reason: String

    /// Such as "--where 'path MATCHES "x"' can't be checked on some events: Can't do regex matching on object 1."
    public var description: String {
        "--where '\(predicate)' can't be checked on some events, which aren't written: \(reason)"
    }
}
