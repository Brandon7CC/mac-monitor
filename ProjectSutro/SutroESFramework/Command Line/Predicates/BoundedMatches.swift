//
//  BoundedMatches.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


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
            let value = try PredicateBridge.evaluate(comparison.leftExpression, with: object, variables: variables)
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
    /// - Throws: ``PredicateFailure`` for a value that isn't a string, or one it gave up on.
    private func matches(_ expression: NSRegularExpression, _ value: Any?,
                         _ options: NSComparisonPredicate.Options) throws -> Bool {
        guard let value, !(value is NSNull) else { return false }
        guard var text = value as? String else {
            throw PredicateFailure(description: "Can't do regex matching on object \(value).")
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
            throw PredicateFailure(description: "MATCHES gave up on a value after \(Self.limit) seconds: its pattern "
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
    /// - Throws: ``PredicateFailure`` if the pattern isn't a regular expression.
    private func pattern(of comparison: NSComparisonPredicate, on object: Any?,
                         _ variables: [String: Any]?) throws -> NSRegularExpression {
        let value = try PredicateBridge.evaluate(comparison.rightExpression, with: object, variables: variables)
        guard let pattern = value as? String else {
            throw PredicateFailure(description: "Can't use \(value ?? "nil") as a regular expression.")
        }
        if let expression = compiled[pattern] { return expression }
        guard let expression = expression(pattern, comparison.options) else {
            throw PredicateFailure(description: "Can't use '\(pattern)' as a regular expression.")
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

    /// - Parameter value: The left side of an `ANY` or `ALL` comparison.
    /// - Returns: Its members.
    /// - Throws: ``PredicateFailure`` if it isn't an array or a set.
    private static func members(of value: Any?) throws -> [Any] {
        switch value {
        case let array as NSArray: return array as [AnyObject]
        case let set as NSSet: return set.allObjects
        default: throw PredicateFailure(description: "ANY and ALL need an array or a set, not \(value ?? "nil").")
        }
    }
}

/// Why a `MATCHES` (``BoundedMatches``) or a `SUBQUERY` (``RelatedEvents``) couldn't be evaluated on a record.
struct PredicateFailure: Error, CustomStringConvertible {
    let description: String
}
