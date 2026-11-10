//
//  StreamFilter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation


// MARK: - Stream filter
/// Which events `macmonitor stream` writes: `--pid`, `--process`, `--signing-id`, `--target`, `--grep`,
/// `--predicate` and `--indicator`.
///
/// An option given more than once matches an event if any of its values does, and an event is written only if every
/// option given matches it: `--process curl --process wget --signing-id '^com\.apple\.'` writes Apple's curl and
/// wget. `--predicate` is the exception. Every one given must match, checked in order until one doesn't.
///
/// A pattern is a regular expression (`NSRegularExpression`), found anywhere in the value unless it's anchored, and
/// case-sensitive unless it starts with `(?i)`. `--predicate` is an `NSPredicate` on the event's record.
///
/// `--indicator` names an indicator in the Mac's set by its name, ignoring case, or its identity: an event whose
/// record lists it, as the Security Extension matched it, is written.
///
/// `--pid`, `--process` and `--target` read the event's header, which every format decodes. `--signing-id`, `--grep`,
/// `--predicate` and `--indicator` read its export record, the line `--format jsonl` writes, so text output with one
/// of them encodes every event's record too, as JSONL output does. Events filtered out were captured and read, so
/// they're never lost.
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
        /// The longest predicate taken, in characters.
        public static let maxLength = 4096
        /// What was typed.
        public let source: String
        /// Who its errors are for.
        private let audience: PredicateAudience
        /// As parsed and checked, before `MATCHES` and `SUBQUERY` are rewritten: what the store can narrow by
        /// (``storePredicate``).
        let parsed: NSPredicate
        private let predicate: NSPredicate
        /// Its `MATCHES` comparisons, which note why one failed.
        private let matches: BoundedMatches
        /// Its `SUBQUERY`s of related events, and the events they kept.
        let related: RelatedEvents

        /// - Parameters:
        ///   - source: The predicate's format.
        ///   - audience: Who its errors are for.
        /// - Throws: ``CommandLineUsageError`` if it's too long, `NSPredicate` can't read it, or it does more than
        ///   compare values.
        public init(_ source: String, for audience: PredicateAudience = .commandLine) throws {
            try self.init(source, for: audience, maxLength: Self.maxLength)
        }

        /// - Parameters:
        ///   - source: The predicate's format.
        ///   - audience: Who its errors are for.
        ///   - maxLength: The longest predicate taken, in characters.
        /// - Throws: ``CommandLineUsageError`` if it's too long, `NSPredicate` can't read it, or it does more than
        ///   compare values.
        init(_ source: String, for audience: PredicateAudience, maxLength: Int) throws {
            let parsed = try Self.parse(source, for: audience, maxLength: maxLength)
            self.parsed = parsed
            matches = BoundedMatches()
            related = RelatedEvents(matches: matches)
            predicate = try matches.rewrite(related.rewrite(parsed, for: audience), for: audience)
            self.source = source
            self.audience = audience
        }

        /// Read a predicate and check it only compares the record's values, without making it ready to evaluate:
        /// what ``IndicatorCompiler`` reads.
        ///
        /// - Parameters:
        ///   - source: The predicate's format.
        ///   - audience: Who its errors are for.
        ///   - maxLength: The longest predicate taken, in characters.
        /// - Returns: The predicate, parsed and checked (``parsed``).
        /// - Throws: ``CommandLineUsageError`` if it's too long, `NSPredicate` can't read it, or it does more than
        ///   compare values.
        static func parse(_ source: String, for audience: PredicateAudience,
                          maxLength: Int = maxLength) throws -> NSPredicate {
            guard source.count <= maxLength else {
                throw CommandLineUsageError("\(audience.name) can't be longer than \(Self.maxLength) characters.",
                                            command: audience.command)
            }
            /// `NSPredicate`'s scanner ends the process on some unclosed strings.
            guard !PredicateText.endsInsideQuote(source) else {
                throw CommandLineUsageError("\(audience.name) can't read '\(source)': a quoted string isn't closed.",
                                            command: audience.command)
            }
            let parsed: NSPredicate
            do {
                /// A boolean key path alone, as in `is_adhoc_signed AND ...`, compared so `NSPredicate` can read it.
                parsed = try PredicateBridge.predicate(withFormat: PredicateText.comparingBooleans(source))
            } catch {
                /// `NSPredicate` ends some reasons with a period and not others.
                let reason = error.localizedDescription.hasSuffix(".") ? error.localizedDescription
                    : error.localizedDescription + "."
                throw CommandLineUsageError("\(audience.name) can't read '\(source)': \(reason)",
                                            command: audience.command)
            }
            try PredicateGuard.check(parsed, for: audience)
            return parsed
        }

        /// Does it compare events with related ones, in a `SUBQUERY`? Then give ``collect(_:)`` every event before
        /// evaluating it on any.
        public var relatesEvents: Bool { !related.isEmpty }

        /// Does it name the record's `indicators` or `indicators_undetermined`? Then its events' records are encoded
        /// with them (``RecordIndicators``), only when it's asked for.
        public var readsIndicators: Bool {
            source.range(of: #"\bindicators(_undetermined)?\b"#, options: .regularExpression) != nil
        }

        /// Does it name the record's `indicators` itself? Then an event without stored verdicts is matched against
        /// every indicator as its record is encoded. One that names only `indicators_undetermined` reads stored
        /// verdicts alone (``RecordIndicators/stored``), since only those list it.
        public var readsIndicatorHits: Bool {
            source.range(of: #"\bindicators\b"#, options: .regularExpression) != nil
        }

        /// Keep an event its `SUBQUERY`s pick as a related event.
        ///
        /// - Parameter record: An event's record.
        /// - Throws: ``StreamFilterError`` if a `SUBQUERY`'s conditions can't be evaluated on it.
        public func collect(_ record: NSDictionary) throws {
            do {
                try related.collect(record)
            } catch {
                throw StreamFilterError(predicate: source, reason: "\(error)")
            }
        }

        /// Evaluate the predicate on a record.
        ///
        /// - Parameter record: The record.
        /// - Returns: Does the record match?
        /// - Throws: ``StreamFilterError`` if the predicate can't be evaluated on it, such as `MATCHES` on a number,
        ///   or on a value it gave up on (``BoundedMatches``).
        public func evaluate(on record: NSDictionary) throws -> Bool {
            matches.failure = nil
            related.failure = nil
            let result: Bool
            do {
                result = try PredicateBridge.evaluate(predicate, with: PredicateRecord(record), variables: nil)
            } catch {
                throw StreamFilterError(predicate: source, reason: error.localizedDescription)
            }
            if let failure = related.failure ?? matches.failure {
                throw StreamFilterError(predicate: source, reason: failure)
            }
            return result
        }

        /// The same predicate, parsed again, for another thread: `NSPredicate` doesn't say it's thread-safe. It has
        /// no related events yet.
        public var copy: Predicate {
            (try? Predicate(source, for: audience, maxLength: .max)) ?? self
        }

        /// A predicate that matches an event only when every source does. Each source is checked on its own first,
        /// so an error names only that source. The sources together may be longer than ``maxLength``.
        ///
        /// - Parameters:
        ///   - sources: The predicates. Blank ones are left out.
        ///   - audience: Who their errors are for.
        /// - Returns: The one source alone, the sources in parentheses joined by `AND`, or `nil` when all are blank.
        /// - Throws: ``CommandLineUsageError`` for the first source that can't be used.
        public static func all(_ sources: [String], for audience: PredicateAudience = .commandLine) throws
            -> Predicate? {
            let parts = try sources.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .map { try Predicate($0, for: audience) }
            return try all(parts, for: audience)
        }

        /// A predicate that matches an event only when every predicate does. The predicates together may be longer
        /// than ``maxLength``.
        ///
        /// - Parameters:
        ///   - predicates: The predicates, each already checked.
        ///   - audience: Who the combined predicate's errors are for.
        /// - Returns: The one predicate alone, the predicates in parentheses joined by `AND`, or `nil` for none.
        /// - Throws: ``CommandLineUsageError`` if they can't be read together.
        public static func all(_ predicates: [Predicate], for audience: PredicateAudience) throws -> Predicate? {
            guard predicates.count > 1 else { return predicates.first }
            return try Predicate(predicates.map { "(\($0.source))" }.joined(separator: " AND "), for: audience,
                                 maxLength: .max)
        }

        /// A predicate that matches an event when any source does. Each source is checked on its own first, and one
        /// that can't be used is left out. The sources together may be longer than ``maxLength``.
        ///
        /// - Parameters:
        ///   - sources: The predicates. Blank ones are left out.
        ///   - audience: Who their errors are for.
        /// - Returns: The one usable source alone, the usable sources in parentheses joined by `OR`, or `nil` when
        ///   none can be used.
        public static func any(_ sources: [String], for audience: PredicateAudience = .commandLine) -> Predicate? {
            let parts = sources.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .compactMap { try? Predicate($0, for: audience) }
            guard parts.count > 1 else { return parts.first }
            return try? Predicate(parts.map { "(\($0.source))" }.joined(separator: " OR "), for: audience,
                                  maxLength: .max)
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
    /// `--predicate`: the event's record.
    public var predicates: [Predicate] = []
    /// `--indicator`: the names, ignoring case, or identities of the indicators the event's record lists.
    public var indicators: [String] = []

    /// No filter: every event is written.
    public init() {}

    /// Does deciding need the event's export record?
    public var readsRecords: Bool {
        !(signingIDs.isEmpty && greps.isEmpty && predicates.isEmpty && indicators.isEmpty)
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

    /// Does an event's record pass `--signing-id`, `--grep`, `--indicator` and `--predicate`?
    ///
    /// - Parameter record: The event's export record.
    /// - Returns: `true` if it does.
    /// - Throws: ``StreamFilterError`` if a `--predicate` can't be evaluated on it. A predicate after one that didn't
    ///   match is never evaluated, so it can't throw.
    public func admits(record: NSDictionary) throws -> Bool {
        let signingID = record.value(forKeyPath: "process.signing_id") as? String ?? ""
        guard Self.any(signingIDs, { $0.matches(signingID) }),
              Self.any(greps, { pattern in Self.containsString(record, where: pattern.matches) }),
              Self.any(indicators, { reference in
                  (record["indicators"] as? [NSDictionary] ?? []).contains { Self.hit($0, isNamed: reference) }
              }) else { return false }
        return try predicates.allSatisfy { try $0.evaluate(on: record) }
    }

    /// Is a record's indicator the one an `--indicator` value names?
    ///
    /// - Parameters:
    ///   - hit: An entry of the record's `indicators`.
    ///   - reference: The value: a name, ignoring case, or an identity.
    /// - Returns: `true` when its name or its identity is the value.
    private static func hit(_ hit: NSDictionary, isNamed reference: String) -> Bool {
        if (hit["name"] as? String)?.caseInsensitiveCompare(reference) == .orderedSame { return true }
        guard let id = (hit["id"] as? String).flatMap(UUID.init(uuidString:)) else { return false }
        return id == UUID(uuidString: reference)
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


/// A `--predicate` that can't be evaluated on an event, which isn't written.
public struct StreamFilterError: Error, Equatable, CustomStringConvertible {
    /// The predicate, as typed.
    public let predicate: String
    /// Why, as `NSPredicate` says.
    public let reason: String

    /// Such as "--predicate 'path MATCHES "x"' can't be checked on some events: Can't do regex matching on object 1."
    public var description: String {
        "--predicate '\(predicate)' can't be checked on some events, which aren't written: \(reason)"
    }
}
