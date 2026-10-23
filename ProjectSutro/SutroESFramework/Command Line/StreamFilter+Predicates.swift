//
//  StreamFilter+Predicates.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/22/26.
//

import Foundation


// MARK: - Data-only predicates
/// Keeps a `--where` predicate to comparing the record's values.
///
/// `NSPredicate`'s format language does more than compare. `FUNCTION(x, 'selector')` calls any Objective-C method,
/// `CAST('NSTask', 'Class')` names any class, a `SUBQUERY` variable reaches key-value coding on any value, and a key
/// path past a value (`path.release`) has key-value coding call that method on it. `macmonitor` runs as root, so a
/// `--where` made from text someone else chose could run code. Two guards make every predicate data-only:
///
/// - ``check(_:)-(NSPredicate)`` refuses, as it's parsed, a predicate with any expression but key paths, constants,
///   sets, `SELF`, and `NSPredicate`'s own arithmetic, string and aggregate functions (``functions``). Each key in a
///   key path must be one the telemetry schema names (``keys``), or an array's aggregate: Foundation ends the process
///   rather than evaluate a key that names a method such as `release`.
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
    /// - Parameter predicate: The parsed predicate.
    /// - Throws: ``CommandLineUsageError`` naming the first part it refuses.
    static func check(_ predicate: NSPredicate) throws {
        switch predicate {
        case let compound as NSCompoundPredicate:
            for case let subpredicate as NSPredicate in compound.subpredicates { try check(subpredicate) }
        case let comparison as NSComparisonPredicate:
            guard comparison.predicateOperatorType != .customSelector else { throw refusal(comparison.predicateFormat) }
            try check(comparison.leftExpression)
            try check(comparison.rightExpression)
        default:
            guard ["TRUEPREDICATE", "FALSEPREDICATE"].contains(predicate.predicateFormat) else {
                throw refusal(predicate.predicateFormat)
            }
        }
    }

    /// Refuse an expression that does more than name or combine the record's values. Each property read is one the
    /// expression's type has: reading another raises.
    ///
    /// - Parameter expression: The expression.
    /// - Throws: ``CommandLineUsageError`` naming the first part it refuses.
    static func check(_ expression: NSExpression) throws {
        switch expression.expressionType {
        case .evaluatedObject, .anyKey:
            return
        case .keyPath:
            try checkKeys(expression.keyPath)
        case .constantValue:
            guard !object_isClass(expression.constantValue) else { throw refusal(expression.description) }
        case .function:
            guard functions.contains(expression.function), isFunctionsClass(expression.operand) else {
                throw refusal(expression.description)
            }
            try expression.arguments?.forEach(check)
        case .aggregate:
            guard let members = expression.collection as? [NSExpression] else { throw refusal(expression.description) }
            try members.forEach(check)
        case .unionSet, .intersectSet, .minusSet:
            try check(expression.left)
            try check(expression.right)
        default:
            /// Variables, SUBQUERY, blocks, TERNARY, and FIRST, LAST and SIZE.
            throw refusal(expression.description)
        }
    }

    /// Refuse a key path with a key no record has.
    ///
    /// - Parameter keyPath: The key path.
    /// - Throws: ``CommandLineUsageError`` naming the first such key, and the one meant if it's close.
    private static func checkKeys(_ keyPath: String) throws {
        for key in keyPath.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        where !keys.contains(key) && !PredicateRecord.aggregates.contains(key) {
            let suggestion = CommandLineSuggestion.didYouMean(key, among: keys.sorted())
            throw CommandLineUsageError("""
                --where can't use '\(keyPath)': '\(key)' isn't a key in Mac Monitor's records.\(suggestion) \
                'macmonitor schema' describes them.
                """, command: "stream")
        }
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
    /// - Parameter part: The part, as `NSPredicate` writes it.
    /// - Returns: The error.
    private static func refusal(_ part: String) -> CommandLineUsageError {
        CommandLineUsageError("""
            --where can't use \(part). It compares the record's values, with NSPredicate's operators and functions \
            such as lowercase(), but doesn't call methods, cast, or take variables, SUBQUERY or indexes: use ANY for \
            an array's values and .@count for its size.
            """, command: "stream")
    }
}


// MARK: - Records for predicates
/// A record as a `--where` predicate sees it. A key path only looks keys up in the record's objects, at any depth: an
/// array's key is each of its objects' key, or its `@count`, `@sum`, `@avg`, `@min` or `@max`, and a value's is
/// `nil`. Plain key-value coding would call any method a key names on a value (`path.release`). Not thread-safe.
final class PredicateRecord: NSObject {
    /// The aggregates an array takes.
    static let aggregates: Set<String> = ["@count", "@sum", "@avg", "@min", "@max"]
    private let values: NSDictionary

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
