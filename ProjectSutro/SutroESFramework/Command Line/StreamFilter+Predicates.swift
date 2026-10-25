//
//  StreamFilter+Predicates.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation


// MARK: - Audience
/// Who a predicate's errors are written for: `macmonitor stream --predicate`, or the predicate search in Mac Monitor's
/// window.
public struct PredicateAudience: Equatable {
    /// What the errors call the predicate, such as "--predicate".
    let name: String
    /// Where the record's keys are described.
    let schema: String
    /// The command whose help the errors point to.
    let command: String?
    /// Can it compare an event with others (``PredicateRelation``)? Only with every event at hand, not in a stream.
    let relatesEvents: Bool

    /// `macmonitor stream --predicate`.
    public static let commandLine = PredicateAudience(name: "--predicate",
                                                      schema: "'macmonitor schema' describes them.",
                                                      command: "stream", relatesEvents: false)
    /// A finding's predicate, in Settings ▸ Findings, which compares one event at a time.
    public static let finding = PredicateAudience(name: "The finding's predicate",
                                                  schema: "Settings ▸ Telemetry Schema describes them.", command: nil,
                                                  relatesEvents: false)
    /// The event tables' predicate search.
    public static let search = PredicateAudience(name: "The predicate",
                                                 schema: "Settings ▸ Telemetry Schema describes them.", command: nil,
                                                 relatesEvents: true)
}


// MARK: - Data-only predicates
/// Keeps a `--predicate` to comparing the record's values.
///
/// `NSPredicate`'s format language does more than compare. `FUNCTION(x, 'selector')` calls any Objective-C method,
/// `CAST('NSTask', 'Class')` names any class, a `SUBQUERY` variable reaches key-value coding on any value, and a key
/// path past a value (`path.release`) has key-value coding call that method on it. `macmonitor` runs as root, so a
/// `--predicate` made from text someone else chose could run code. Two guards make every predicate data-only:
///
/// - ``check(_:for:in:)-(NSPredicate,_,_)`` refuses, as it's parsed, a predicate with any expression but key paths,
///   constants, sets, `SELF`, and `NSPredicate`'s own arithmetic, string and aggregate functions (``functions``).
///   Each key in a key path must be one the telemetry schema names (``keys``), or an array's aggregate: Foundation
///   ends the process rather than evaluate a key that names a method such as `release`. The search may also take a
///   `SUBQUERY` of related events (``PredicateRelation``), whose variable is only read for key paths: each of its
///   values is a ``PredicateRecord`` (``RelatedEvents``).
/// - ``PredicateRecord`` is what it's evaluated on: its key paths only look keys up in the record's objects, so
///   key-value coding never calls a method on a value.
enum PredicateGuard {
    /// `NSPredicate`'s own functions a predicate may use, by selector: arithmetic, bitwise, aggregates, case, and the
    /// time. Not `castObject:toType:` (CAST), and not the ones index syntax (`args[1]`) makes, which can't evaluate on
    /// a record's nested arrays anyway.
    static let functions: Set<String> = [
        "add:to:", "from:subtract:", "multiply:by:", "divide:by:", "modulus:by:", "abs:", "sqrt:", "log:", "ln:",
        "exp:", "raise:toPower:", "floor:", "ceiling:", "trunc:", "bitwiseAnd:with:", "bitwiseOr:with:",
        "bitwiseXor:with:", "leftshift:by:", "rightshift:by:", "onesComplement:", "count:", "sum:", "average:", "min:",
        "max:", "median:", "mode:", "stddev:", "lowercase:", "uppercase:", "now"
    ]
    /// The class `NSPredicate` calls its own functions on. `FUNCTION` calls them on whatever it's given instead.
    static let functionsClass = "_NSPredicateUtilities"
    /// Every key a record can have: each object's properties in the bundled telemetry schema. None if it can't be
    /// read, so every key path is refused.
    static let keys: Set<String> = {
        guard let data = try? TelemetrySchema.data(), let schema = try? JSONSerialization.jsonObject(with: data) else {
            return []
        }
        var keys = Set<String>()
        /// Each `properties` object's names, at any depth.
        func collect(_ value: Any) {
            switch value {
            case let object as [String: Any]:
                if let properties = object["properties"] as? [String: Any] { keys.formUnion(properties.keys) }
                object.values.forEach(collect)
            case let array as [Any]:
                array.forEach(collect)
            default:
                break
            }
        }
        collect(schema)
        return keys
    }()

    /// Refuse a predicate that does more than compare the record's values.
    ///
    /// - Parameters:
    ///   - predicate: The parsed predicate.
    ///   - audience: Who the error is for.
    ///   - variable: The variable of the `SUBQUERY` it's in, if it is.
    /// - Throws: ``CommandLineUsageError`` naming the first part it refuses.
    static func check(_ predicate: NSPredicate, for audience: PredicateAudience, in variable: String? = nil) throws {
        switch predicate {
        case let compound as NSCompoundPredicate:
            for case let subpredicate as NSPredicate in compound.subpredicates {
                try check(subpredicate, for: audience, in: variable)
            }
        case let comparison as NSComparisonPredicate:
            guard comparison.predicateOperatorType != .customSelector else {
                throw refusal(comparison.predicateFormat, for: audience)
            }
            try check(comparison.leftExpression, for: audience, in: variable)
            try check(comparison.rightExpression, for: audience, in: variable)
        default:
            guard ["TRUEPREDICATE", "FALSEPREDICATE"].contains(predicate.predicateFormat) else {
                throw refusal(predicate.predicateFormat, for: audience)
            }
        }
    }

    /// Refuse an expression that does more than name or combine the record's values. Each property read is one the
    /// expression's type has: reading another raises.
    ///
    /// - Parameters:
    ///   - expression: The expression.
    ///   - audience: Who the error is for.
    ///   - variable: The variable of the `SUBQUERY` it's in, if it is.
    /// - Throws: ``CommandLineUsageError`` naming the first part it refuses.
    static func check(_ expression: NSExpression, for audience: PredicateAudience, in variable: String? = nil) throws {
        switch expression.expressionType {
        case .evaluatedObject, .anyKey:
            return
        case .keyPath:
            try checkKeys(expression.keyPath, for: audience)
        case .constantValue:
            guard !object_isClass(expression.constantValue) else {
                throw refusal(expression.description, for: audience)
            }
        case .function where expression.function == "valueForKeyPath:":
            /// `$e.path`, a related event's key path, or `SUBQUERY(…).@count`.
            guard let path = expression.arguments?.first, expression.arguments?.count == 1 else {
                throw refusal(expression.description, for: audience)
            }
            switch expression.operand.expressionType {
            case .variable where variable != nil && expression.operand.variable == variable:
                try checkKeys(path.keyPath, for: audience, of: variable)
            case .subquery where path.keyPath == "@count":
                try check(expression.operand, for: audience, in: variable)
            default:
                throw refusal(expression.description, for: audience)
            }
        case .function:
            guard functions.contains(expression.function), isFunctionsClass(expression.operand) else {
                throw refusal(expression.description, for: audience)
            }
            try expression.arguments?.forEach { try check($0, for: audience, in: variable) }
        case .subquery:
            try checkSubquery(expression, for: audience, in: variable)
        case .aggregate:
            guard let members = expression.collection as? [NSExpression] else {
                throw refusal(expression.description, for: audience)
            }
            try members.forEach { try check($0, for: audience, in: variable) }
        case .unionSet, .intersectSet, .minusSet:
            try check(expression.left, for: audience, in: variable)
            try check(expression.right, for: audience, in: variable)
        default:
            /// Variables outside `$e.path`, blocks, TERNARY, and FIRST, LAST and SIZE.
            throw refusal(expression.description, for: audience)
        }
    }

    /// Refuse a `SUBQUERY` but one of related events, `SUBQUERY(process_group, $e, …)`, whose variable is only read
    /// for key paths, outside another.
    ///
    /// - Parameters:
    ///   - subquery: The `SUBQUERY`.
    ///   - audience: Who the error is for.
    ///   - variable: The variable of the `SUBQUERY` it's in, if it is.
    /// - Throws: ``CommandLineUsageError`` saying why it's refused.
    private static func checkSubquery(_ subquery: NSExpression, for audience: PredicateAudience,
                                      in variable: String?) throws {
        guard audience.relatesEvents else { throw relationsRefusal(subquery.description, for: audience) }
        guard variable == nil else {
            throw CommandLineUsageError("""
                \(audience.name) can't put a SUBQUERY inside another: compare the related events in one.
                """, command: audience.command)
        }
        guard let collection = subquery.collection as? NSExpression, collection.expressionType == .keyPath,
              PredicateRelation(rawValue: collection.keyPath) != nil else {
            throw CommandLineUsageError("""
                \(audience.name) can't use \(subquery.description): a SUBQUERY goes through related events, one of \
                \(PredicateRelation.names), as in SUBQUERY(process_group, $e, $e.es_event_type == \
                "ES_EVENT_TYPE_NOTIFY_CREATE").@count > 0.
                """, command: audience.command)
        }
        try check(subquery.predicate, for: audience, in: subquery.variable)
    }

    /// Refuse a key path with a key no record has.
    ///
    /// - Parameters:
    ///   - keyPath: The key path.
    ///   - audience: Who the error is for.
    /// - Throws: ``CommandLineUsageError`` naming the first such key, and the one meant if it's close.
    private static func checkKeys(_ keyPath: String, for audience: PredicateAudience,
                                  of variable: String? = nil) throws {
        if variable == nil, let first = keyPath.split(separator: ".").first,
           let relation = PredicateRelation(rawValue: String(first)) {
            guard audience.relatesEvents else { throw relationsRefusal("'\(keyPath)'", for: audience) }
            throw CommandLineUsageError("""
                \(audience.name) can't use '\(keyPath)': \(relation.rawValue) is related events, compared in a \
                SUBQUERY, as in SUBQUERY(\(relation.rawValue), $e, $e.es_event_type == \
                "ES_EVENT_TYPE_NOTIFY_EXEC").@count > 0.
                """, command: audience.command)
        }
        /// `$e.` before a related event's key path, as typed.
        let lead = variable.map { "$\($0)." } ?? ""
        let path = keyPath.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        for key in path where !keys.contains(key) && !PredicateRecord.aggregates.contains(key) {
            let suggestion = CommandLineSuggestion.didYouMean(key, among: keys.sorted())
            throw CommandLineUsageError("""
                \(audience.name) can't use '\(lead)\(keyPath)': '\(key)' isn't a key in Mac Monitor's records.\
                \(suggestion) \(audience.schema)
                """, command: audience.command)
        }
        /// Each key is a record's somewhere: is it where the key path puts it?
        let valid = RecordKeyPaths.shared.validCount(of: path)
        guard valid < path.count else { return }
        let parent = path.prefix(valid).filter { !$0.hasPrefix("@") }.joined(separator: ".")
        let place = parent.isEmpty ? "'\(path[valid])' isn't a key at the top of a record"
            : "'\(lead)\(parent)' has no key '\(path[valid])'"
        let meant = RecordKeyPaths.shared.suggestion(for: path).map { " Did you mean '\(lead)\($0)'?" } ?? ""
        throw CommandLineUsageError("""
            \(audience.name) can't use '\(lead)\(keyPath)': \(place).\(meant) \(audience.schema)
            """, command: audience.command)
    }

    /// Is an expression `NSPredicate`'s own functions class, as the operand of a function it parsed?
    ///
    /// - Parameter operand: A function's operand.
    /// - Returns: `true` for the class, `false` for anything `FUNCTION` was given.
    private static func isFunctionsClass(_ operand: NSExpression) -> Bool {
        guard operand.expressionType == .constantValue, let value = operand.constantValue, object_isClass(value),
              let type = value as? AnyClass else { return false }
        return NSStringFromClass(type) == functionsClass
    }

    /// The usage error for a part of a predicate that's refused.
    ///
    /// - Parameters:
    ///   - part: The part, as `NSPredicate` writes it.
    ///   - audience: Who the error is for.
    /// - Returns: The error.
    private static func refusal(_ part: String, for audience: PredicateAudience) -> CommandLineUsageError {
        let subquery = audience.relatesEvents ? "variables outside a SUBQUERY of related events" : "variables, SUBQUERY"
        return CommandLineUsageError("""
            \(audience.name) can't use \(part). It compares the record's values, with NSPredicate's operators and \
            functions such as lowercase(), but doesn't call methods, cast, or take \(subquery) or indexes: use ANY \
            for an array's values and .@count for its size.
            """, command: audience.command)
    }

    /// - Parameters:
    ///   - part: The `SUBQUERY` or related events, as `NSPredicate` writes it.
    ///   - audience: Who the error is for, which can't relate events.
    /// - Returns: The usage error for a `SUBQUERY` or related events.
    private static func relationsRefusal(_ part: String, for audience: PredicateAudience) -> CommandLineUsageError {
        CommandLineUsageError("""
            \(audience.name) can't use \(part). It compares one event at a time: related events \
            (\(PredicateRelation.names)) and SUBQUERY need every event at hand, in Mac Monitor's predicate search.
            """, command: audience.command)
    }
}


// MARK: - Regular expressions with a time limit
/// `MATCHES`, with a time limit on each value.
///
/// `NSPredicate` matches a regular expression for as long as it takes, so a pattern that backtracks without end, such
/// as `(a+)+b` on a long run of `a`s, would hold up the stream, or the event tables' search, until it finished. This
/// replaces each `MATCHES` comparison with one that matches with `NSRegularExpression`, which reports its progress, and
/// gives up on a value after ``limit``. A value it gives up on, or can't match (a number), fails the evaluation, as one
/// `NSPredicate`'s own `MATCHES` can't match does. Not thread-safe: each ``StreamFilter/Predicate`` has its own.
final class BoundedMatches {
    /// The longest one value is matched for.
    static let limit: TimeInterval = 0.5
    /// The most patterns read from records it keeps compiled.
    private static let cacheSize = 64

    /// Why a `MATCHES` failed during the evaluation in progress, if one did.
    var failure: String?
    /// Patterns read from records, compiled.
    private var compiled: [String: NSRegularExpression] = [:]

    /// Why a value couldn't be matched.
    private struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    /// Replace each `MATCHES` in a predicate.
    ///
    /// - Parameters:
    ///   - predicate: A predicate ``PredicateGuard`` passed.
    ///   - audience: Who an error is for.
    /// - Returns: The predicate, matching with a time limit.
    /// - Throws: ``CommandLineUsageError`` for a pattern that isn't a regular expression.
    func rewrite(_ predicate: NSPredicate, for audience: PredicateAudience) throws -> NSPredicate {
        switch predicate {
        case let compound as NSCompoundPredicate:
            let subpredicates = try compound.subpredicates.compactMap { $0 as? NSPredicate }
                .map { try rewrite($0, for: audience) }
            return NSCompoundPredicate(type: compound.compoundPredicateType, subpredicates: subpredicates)
        case let comparison as NSComparisonPredicate where comparison.predicateOperatorType == .matches:
            var constant: NSRegularExpression?
            if comparison.rightExpression.expressionType == .constantValue {
                guard let pattern = comparison.rightExpression.constantValue as? String,
                      let expression = expression(pattern, comparison.options) else {
                    throw CommandLineUsageError("""
                        \(audience.name) can't use \(comparison.predicateFormat): its pattern isn't a regular \
                        expression.
                        """, command: audience.command)
                }
                constant = expression
            }
            return NSPredicate { object, variables in self.evaluate(comparison, constant, on: object, variables) }
        default:
            return predicate
        }
    }

    /// Evaluate one `MATCHES` comparison, noting why it failed if it did.
    ///
    /// - Parameters:
    ///   - comparison: The comparison.
    ///   - constant: Its pattern compiled, when it's a constant.
    ///   - object: What it's evaluated on.
    ///   - variables: A `SUBQUERY`'s variable, when it's in one.
    /// - Returns: Does the object match? `false` once anything failed.
    private func evaluate(_ comparison: NSComparisonPredicate, _ constant: NSRegularExpression?,
                          on object: Any?, _ variables: [String: Any]?) -> Bool {
        guard failure == nil else { return false }
        do {
            let value = try Self.value(of: comparison.leftExpression, on: object, variables)
            let expression = try constant ?? pattern(of: comparison, on: object, variables)
            let options = comparison.options
            switch comparison.comparisonPredicateModifier {
            case .any: return try Self.members(of: value).contains { try matches(expression, $0, options) }
            case .all: return try Self.members(of: value).allSatisfy { try matches(expression, $0, options) }
            default: return try matches(expression, value, options)
            }
        } catch {
            failure = "\(error)"
            return false
        }
    }

    /// Does a value match a regular expression, all of it, within ``limit``?
    ///
    /// - Parameters:
    ///   - expression: The regular expression, anchored at both ends.
    ///   - value: The value: `nil` never matches.
    ///   - options: The comparison's options: `[d]` matches the value without its diacritics.
    /// - Returns: `true` if it matches.
    /// - Throws: ``Failure`` for a value that isn't a string, or one it gave up on.
    private func matches(_ expression: NSRegularExpression, _ value: Any?,
                         _ options: NSComparisonPredicate.Options) throws -> Bool {
        guard let value, !(value is NSNull) else { return false }
        guard var text = value as? String else {
            throw Failure(description: "Can't do regex matching on object \(value).")
        }
        if options.contains(.diacriticInsensitive) { text = text.folding(options: .diacriticInsensitive, locale: nil) }
        let deadline = Date(timeIntervalSinceNow: Self.limit)
        var matched = false, gaveUp = false
        expression.enumerateMatches(in: text, options: [.reportProgress, .anchored],
                                    range: NSRange(location: 0, length: (text as NSString).length)) { result, _, stop in
            if result != nil {
                matched = true
                stop.pointee = true
            } else if Date() >= deadline {
                gaveUp = true
                stop.pointee = true
            }
        }
        guard !gaveUp else {
            throw Failure(description: "MATCHES gave up on a value after \(Self.limit) seconds: its pattern "
                          + "backtracks too much.")
        }
        return matched
    }

    /// A pattern read from the record, compiled.
    ///
    /// - Parameters:
    ///   - comparison: The comparison, whose right side isn't a constant.
    ///   - object: What it's evaluated on.
    ///   - variables: A `SUBQUERY`'s variable, when it's in one.
    /// - Returns: The regular expression.
    /// - Throws: ``Failure`` if the pattern isn't a regular expression.
    private func pattern(of comparison: NSComparisonPredicate, on object: Any?,
                         _ variables: [String: Any]?) throws -> NSRegularExpression {
        let value = try Self.value(of: comparison.rightExpression, on: object, variables)
        guard let pattern = value as? String else {
            throw Failure(description: "Can't use \(value ?? "nil") as a regular expression.")
        }
        if let expression = compiled[pattern] { return expression }
        guard let expression = expression(pattern, comparison.options) else {
            throw Failure(description: "Can't use '\(pattern)' as a regular expression.")
        }
        if compiled.count >= Self.cacheSize { compiled.removeAll() }
        compiled[pattern] = expression
        return expression
    }

    /// Compile a pattern to match all of a value, as `MATCHES` does.
    ///
    /// - Parameters:
    ///   - pattern: The pattern.
    ///   - options: The comparison's options: `[c]` ignores case, `[d]` diacritics.
    /// - Returns: The regular expression, or `nil` if the pattern isn't one.
    private func expression(_ pattern: String, _ options: NSComparisonPredicate.Options) -> NSRegularExpression? {
        let pattern = options.contains(.diacriticInsensitive)
            ? pattern.folding(options: .diacriticInsensitive, locale: nil) : pattern
        /// On its own first, so a stray parenthesis isn't balanced by the anchoring group.
        guard (try? NSRegularExpression(pattern: pattern)) != nil else { return nil }
        return try? NSRegularExpression(pattern: "\\A(?:\(pattern))\\z",
                                        options: options.contains(.caseInsensitive) ? .caseInsensitive : [])
    }

    /// - Parameters:
    ///   - expression: One side of a comparison.
    ///   - object: What it's evaluated on.
    ///   - variables: A `SUBQUERY`'s variable, when it's in one.
    /// - Returns: Its value.
    /// - Throws: Why `NSExpression` couldn't evaluate it.
    private static func value(of expression: NSExpression, on object: Any?,
                              _ variables: [String: Any]?) throws -> Any? {
        var value: AnyObject?
        try PredicateBridge.evaluate(expression, with: object, variables: variables, value: &value)
        return value
    }

    /// - Parameter value: The left side of an `ANY` or `ALL` comparison.
    /// - Returns: Its members.
    /// - Throws: ``Failure`` if it isn't an array or a set.
    private static func members(of value: Any?) throws -> [Any] {
        switch value {
        case let array as NSArray: return array as [AnyObject]
        case let set as NSSet: return set.allObjects
        default: throw Failure(description: "ANY and ALL need an array or a set, not \(value ?? "nil").")
        }
    }
}


// MARK: - Events
public extension StreamFilter.Predicate {
    /// Every key a predicate's key paths may name: each object's properties in the telemetry schema, an array's
    /// aggregates (`@count`), and the related events a `SUBQUERY` goes through.
    static var recordKeys: Set<String> {
        PredicateGuard.keys.union(PredicateRecord.aggregates).union(PredicateRelation.allCases.map(\.rawValue))
    }
    
    /// Evaluate the predicate on an event's record, the JSON Export telemetry writes for it.
    ///
    /// Call on the event's context's queue. Prefetch ``ESMessage/recordPrefetchKeyPaths(in:)`` for many events.
    ///
    /// - Parameter message: The event.
    /// - Returns: Does its record match?
    /// - Throws: ``StreamFilterError`` if the predicate can't be evaluated on it, or the encoder's error.
    func evaluate(on message: ESMessage) throws -> Bool {
        try evaluate(on: Self.record(of: message))
    }

    /// Keep an event the predicate's `SUBQUERY`s pick as a related event (``collect(_:)``).
    ///
    /// Call on the event's context's queue, for every event before evaluating the predicate on any.
    ///
    /// - Parameter message: The event.
    /// - Throws: ``StreamFilterError`` if a `SUBQUERY`'s conditions can't be evaluated on it, or the encoder's error.
    func collect(_ message: ESMessage) throws {
        try collect(Self.record(of: message))
    }

    /// - Parameter message: An event.
    /// - Returns: Its record, the JSON Export telemetry writes for it.
    /// - Throws: The encoder's error.
    private static func record(of message: ESMessage) throws -> NSDictionary {
        try JSONSerialization.jsonObject(with: JSONEncoder().encode(message)) as? NSDictionary ?? NSDictionary()
    }
}


// MARK: - Records for predicates
/// A record as a predicate sees it. A key path only looks keys up in the record's objects, at any depth: an array's
/// key is each of its objects' key, or its `@count`, `@sum`, `@avg`, `@min` or `@max`, and a value's is `nil`. Plain
/// key-value coding would call any method a key names on a value (`path.release`). Not thread-safe.
final class PredicateRecord: NSObject {
    /// The aggregates an array takes.
    static let aggregates: Set<String> = ["@count", "@sum", "@avg", "@min", "@max"]
    /// The JSON object.
    let values: NSDictionary

    /// - Parameter values: A JSON object.
    init(_ values: NSDictionary) {
        self.values = values
    }

    /// A JSON value as a predicate sees it: objects as records, and arrays with their objects as records.
    ///
    /// - Parameter value: The value.
    /// - Returns: What a predicate compares.
    static func wrap(_ value: Any?) -> Any? {
        switch value {
        case let object as NSDictionary: return PredicateRecord(object)
        case let array as NSArray: return array.map { wrap($0) ?? NSNull() } as NSArray
        default: return value
        }
    }

    /// One key of a value: a record's key, an array's aggregate or each of its records' key, and `nil` for anything
    /// else.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - key: The key.
    /// - Returns: The key's value.
    static func value(of value: Any?, forKey key: String) -> Any? {
        switch value {
        case let record as PredicateRecord:
            return record.value(forKey: key)
        case let array as NSArray where aggregates.contains(key):
            guard key != "@count" else { return array.count }
            /// On numbers only, whose `self` is all key-value coding calls.
            return (array.filter { $0 is NSNumber } as NSArray).value(forKeyPath: key + ".self")
        case let array as NSArray:
            return array.map { (($0 as? PredicateRecord)?.value(forKey: key)) ?? NSNull() } as NSArray
        default:
            return nil
        }
    }

    /// A key's value, never a method's.
    ///
    /// - Parameter key: The key.
    /// - Returns: The value, or the object's `@count`.
    override func value(forKey key: String) -> Any? {
        key == "@count" ? values.count : Self.wrap(values[key])
    }

    /// A key path's value, a key at a time.
    ///
    /// - Parameter keyPath: The key path.
    /// - Returns: The value, or `nil` past a value.
    override func value(forKeyPath keyPath: String) -> Any? {
        keyPath.split(separator: ".", omittingEmptySubsequences: false)
            .reduce(self as Any?) { value, key in Self.value(of: value, forKey: String(key)) }
    }

    /// No key is undefined: one the record lacks is `nil`.
    ///
    /// - Parameter key: The key.
    /// - Returns: `nil`.
    override func value(forUndefinedKey key: String) -> Any? {
        nil
    }
}
