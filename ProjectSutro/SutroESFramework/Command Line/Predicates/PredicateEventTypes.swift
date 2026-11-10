//
//  PredicateEventTypes.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Event types a predicate names
/// The event types a predicate can match, read from its `es_event_type` comparisons and its payload tests, so a
/// matcher looks only at the indicators an event's type can match: ``IndicatorMatcher`` in Mac Monitor, and
/// ``CompiledIndicators`` in the Security Extension, which runs only indicators that name their types.
///
/// A payload test names a type by the key its record's `event` has: `event.btm_launch_item_add != nil` is true only
/// of an `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`, and `== nil` only of any other type.
enum PredicateEventTypes {
    /// Each event type's payload key path, `event.` and the type in lowercase without `ES_EVENT_TYPE_NOTIFY_`, and
    /// the type's name, read from the telemetry schema: a record's `event` has only its own type's key.
    static let payloads: [String: String] = Dictionary(uniqueKeysWithValues: RecordSchema.paths.keys.compactMap {
        let parts = $0.split(separator: ".")
        guard parts.count == 2, parts[0] == "event" else { return nil }
        return ($0, "ES_EVENT_TYPE_NOTIFY_" + parts[1].uppercased())
    })

    /// The event type a payload test names.
    ///
    /// - Parameter comparison: A comparison.
    /// - Returns: The type's name, and whether the comparison is `!= nil`, which only an event of the type passes,
    ///   rather than `== nil`. `nil` for any other comparison.
    static func payloadTest(_ comparison: NSComparisonPredicate) -> (name: String, isPresent: Bool)? {
        let left = comparison.leftExpression, right = comparison.rightExpression
        guard left.expressionType == .keyPath, let name = payloads[left.keyPath],
              comparison.comparisonPredicateModifier == .direct, comparison.options.isEmpty,
              right.expressionType == .constantValue, right.constantValue == nil || right.constantValue is NSNull
        else { return nil }
        switch comparison.predicateOperatorType {
        case .notEqualTo: return (name, true)
        case .equalTo: return (name, false)
        default: return nil
        }
    }

    /// The event types a predicate can match, when it names them: `es_event_type ==` or `IN` a constant, or a
    /// payload's `!= nil`, in a part every match passes. Every indicator Mac Monitor ships names them.
    ///
    /// - Parameter predicate: A parsed predicate.
    /// - Returns: The types, or `nil` when any type can match.
    static func eventTypes(of predicate: NSPredicate) -> Set<String>? {
        switch predicate {
        case let compound as NSCompoundPredicate:
            let parts = compound.subpredicates.compactMap { ($0 as? NSPredicate).map(eventTypes) }
            switch compound.compoundPredicateType {
            case .and:
                return parts.compactMap { $0 }.reduce(nil) { found, types in found?.intersection(types) ?? types }
            case .or:
                guard parts.count == compound.subpredicates.count, !parts.contains(where: { $0 == nil }) else {
                    return nil
                }
                return parts.compactMap { $0 }.reduce(into: Set()) { $0.formUnion($1) }
            default:
                return nil
            }
        case let comparison as NSComparisonPredicate:
            if let test = payloadTest(comparison) { return test.isPresent ? [test.name] : nil }
            guard [.equalTo, .in].contains(comparison.predicateOperatorType) else { return nil }
            return names(in: comparison)
        default:
            return nil
        }
    }

    /// Every event type name a predicate compares `es_event_type` with, or tests the payload of, wherever the
    /// comparison sits: under `AND`, `OR` and `NOT` alike, and with `==`, `!=` or `IN`. A request's indicator is
    /// checked against these, so a misspelt name in any branch is refused rather than compiled as a test that's never
    /// true.
    ///
    /// - Parameter predicate: A parsed predicate.
    /// - Returns: The names, which may be empty.
    static func namedEventTypes(in predicate: NSPredicate) -> Set<String> {
        switch predicate {
        case let compound as NSCompoundPredicate:
            return compound.subpredicates.reduce(into: Set()) { found, part in
                if let part = part as? NSPredicate { found.formUnion(namedEventTypes(in: part)) }
            }
        case let comparison as NSComparisonPredicate:
            return payloadTest(comparison).map { [$0.name] } ?? names(in: comparison) ?? []
        default:
            return []
        }
    }

    /// - Parameter comparison: A comparison.
    /// - Returns: The names an exact `es_event_type ==`, `!=` or `IN` comparison holds, or `nil` for any other
    ///   comparison, or one whose constants aren't all strings.
    private static func names(in comparison: NSComparisonPredicate) -> Set<String>? {
        guard comparison.leftExpression.expressionType == .keyPath,
              comparison.leftExpression.keyPath == "es_event_type",
              comparison.comparisonPredicateModifier == .direct, comparison.options.isEmpty else { return nil }
        let right = comparison.rightExpression
        switch comparison.predicateOperatorType {
        case .equalTo, .notEqualTo:
            return (right.expressionType == .constantValue ? right.constantValue as? String : nil).map { [$0] }
        case .in:
            let values: [Any]?
            switch right.expressionType {
            case .aggregate: values = (right.collection as? [NSExpression])?.map { $0.constantValue as Any }
            case .constantValue: values = (right.constantValue as? NSArray).map { Array($0) }
            default: values = nil
            }
            let names = values?.compactMap { $0 as? String }
            return names.flatMap { $0.count == values?.count ? Set($0) : nil }
        default:
            return nil
        }
    }
}
