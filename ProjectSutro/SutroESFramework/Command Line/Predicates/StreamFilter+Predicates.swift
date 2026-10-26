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
    /// Every key a record can have: each of the telemetry schema's key paths' keys (``RecordKeyPaths``). None if it
    /// can't be read, so every key path is refused.
    static let keys = Set(RecordKeyPaths.shared.nodes.values.flatMap(\.children))

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
        case .aggregate where expression.collection is [NSExpression], .unionSet, .intersectSet, .minusSet:
            try expression.subexpressions.forEach { try check($0, for: audience, in: variable) }
        default:
            /// Variables outside `$e.path`, blocks, TERNARY, FIRST, LAST and SIZE, and an aggregate of anything but
            /// expressions.
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
