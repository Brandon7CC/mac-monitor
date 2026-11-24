//
//  FieldFilterConflicts.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation
import EndpointSecurity


// MARK: - Rules a field filter starves
/// An indicator's rule that can never match while a field filter is on: every event it could match is one the
/// filter leaves out before indicators see it.
///
/// A field filter never removes an event type, only some of its events (``FieldFilter``): only modified closes
/// leaves out the closes of unmodified files. Most rules on closes just see fewer of them. A rule that runs on
/// closes alone and asks for an unmodified one sees none, and a sequence with such a step never completes, unless
/// it's an unordered one that the steps left can still complete.
public struct FieldFilterConflict: Hashable, Sendable {
    /// The indicator.
    public let indicator: UUID
    /// The indicator's name.
    public let name: String
    /// The step that can't match, for a sequence.
    public let step: String?
    /// The filter that leaves its events out.
    public let filter: FieldFilter

    /// What it means for the indicator, as Settings and `macmonitor` say it: “Name” can't match, or can't
    /// complete, and what it needs.
    public var explanation: String {
        let needs = "needs the \(filter.leftOutNoun) of a file"
        guard let step else { return "“\(name)” can't match: it \(needs)." }
        return "“\(name)” can't complete: its step \(step) \(needs)."
    }
}


extension FieldFilter {
    /// The rules that can never match while some filters are on, among the indicators that are on.
    ///
    /// - Parameters:
    ///   - filters: The filters that are on.
    ///   - indicators: The Mac's indicators.
    /// - Returns: One for each rule on one event, and one for each step of a sequence that can't complete without
    ///   it, in the indicators' order. An unordered sequence completes on `atLeast` of its steps, so its starved
    ///   steps are named only when fewer than that are left.
    public static func conflicts(of filters: Set<FieldFilter>, with indicators: [Indicator]) -> [FieldFilterConflict] {
        let on = allCases.filter(filters.contains)
        guard !on.isEmpty else { return [] }
        return indicators.filter(\.isEnabled).flatMap { indicator -> [FieldFilterConflict] in
            let rules: [(step: String?, predicate: String)]
            var spare = 0
            switch indicator.rule {
            case .event(let predicate):
                rules = [(nil, predicate)]
            case .sequence(let sequence):
                rules = sequence.steps.map { ($0.name, $0.predicate) }
                if sequence.order == .unordered { spare = sequence.steps.count - sequence.atLeast }
            }
            let starved = rules.filter { rule in on.contains { $0.starves(rule.predicate) } }
            guard starved.count > spare else { return [] }
            return starved.flatMap { rule in
                on.filter { $0.starves(rule.predicate) }.map {
                    FieldFilterConflict(indicator: indicator.id, name: indicator.name, step: rule.step, filter: $0)
                }
            }
        }
    }

    /// The field the filter checks, as indicators read it, and the value an event it lets through has.
    private var kept: (field: IndicatorField, value: Bool) {
        switch self {
        case .modifiedCloses: return (.closeModified, true)
        }
    }

    /// Can a predicate match none of the events the filter lets through, though it could match one it leaves out?
    ///
    /// The predicate is read as the Security Extension reads it, then asked what it comes to for an event of the
    /// filter's type, with the filter's field set each way and everything else unknown. A predicate that runs on
    /// another event type too can still match those, and one that can't be read matches nothing either way.
    ///
    /// - Parameter source: A rule's predicate.
    /// - Returns: Whether the filter starves it.
    func starves(_ source: String) -> Bool {
        guard let parsed = try? StreamFilter.Predicate.parse(source, for: .indicator),
              let names = PredicateEventTypes.eventTypes(of: parsed),
              names == [eventTypeToString(from: event)] else { return false }
        var drafting = IndicatorDraft.Builder()
        guard let draft = try? drafting.draft(parsed).flattened else { return false }
        let type = Int(event.rawValue)
        return draft.truth(type: type, field: kept.field, is: kept.value) == false
            && draft.truth(type: type, field: kept.field, is: !kept.value) != false
    }
}


extension IndicatorDraft {
    /// What a predicate comes to for an event when only its type and one Boolean field are known.
    ///
    /// - Parameters:
    ///   - type: The event's type, by number.
    ///   - field: The field that's known.
    ///   - value: The field's value.
    /// - Returns: `true` or `false` when the rest of the event can't change it, and `nil` when it can.
    func truth(type: Int, field: IndicatorField, is value: Bool) -> Bool? {
        switch self {
        case .truth(let truth):
            return truth
        case .not(let child):
            return child.truth(type: type, field: field, is: value).map { !$0 }
        case .and(let children):
            let truths = children.map { $0.truth(type: type, field: field, is: value) }
            return truths.contains(false) ? false : truths.allSatisfy { $0 == true } ? true : nil
        case .or(let children):
            let truths = children.map { $0.truth(type: type, field: field, is: value) }
            return truths.contains(true) ? true : truths.allSatisfy { $0 == false } ? false : nil
        case .eventType(let op, let types):
            return Self.truth(of: op, contains: types.contains(type))
        case .compare(let comparison) where comparison.field == field && !comparison.isAny:
            /// By value, as the Security Extension compares numbers: 1.0 is YES.
            let wanted: Double = value ? 1 : 0
            let contains = comparison.constants.contains { constant in
                if case .number(let number, _) = constant { return number == wanted }
                return false
            }
            return Self.truth(of: comparison.op, contains: contains)
        case .compare, .compareFields:
            return nil
        }
    }

    /// What `==`, `IN` or `!=` comes to, given whether the value is among the constants.
    ///
    /// - Parameters:
    ///   - op: The operator.
    ///   - contains: Is the value among the constants?
    /// - Returns: The truth, or `nil` for an operator that orders or searches.
    private static func truth(of op: IndicatorProgram.Operator, contains: Bool) -> Bool? {
        switch op {
        case .equalTo, .in: return contains
        case .notEqualTo: return !contains
        default: return nil
        }
    }
}
