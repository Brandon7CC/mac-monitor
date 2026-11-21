//
//  IndicatorDraft+Shaping.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Shaping a draft
/// What ``IndicatorCompiler`` does to a draft once it's read, before it's laid out: nested `AND`s and `OR`s made one,
/// type checks joined or dropped, and each `AND`'s and `OR`'s children ordered by what reading them can cost.
extension IndicatorDraft {
    /// The same, with an `AND` inside an `AND`, or an `OR` inside an `OR`, made one: `(a AND b) AND c` is
    /// `a AND b AND c`. An `OR`'s type checks are one too, where the first was: `event.create != nil OR
    /// event.rename != nil` is `es_event_type IN` both, which a top-level `AND` then drops (``removingTypeChecks``).
    /// Each child is flattened once: twice doubled the work at every level of `AND`s and `OR`s nested in turn.
    var flattened: IndicatorDraft {
        switch self {
        case .and(let children):
            return .and(children.flatMap { child -> [IndicatorDraft] in
                let flat = child.flattened
                if case .and(let inner) = flat { return inner }
                return [flat]
            })
        case .or(let children):
            return Self.joiningTypeChecks(children.flatMap { child -> [IndicatorDraft] in
                let flat = child.flattened
                if case .or(let inner) = flat { return inner }
                return [flat]
            })
        case .not(let child):
            return .not(child.flattened)
        default:
            return self
        }
    }

    /// - Parameter children: An `OR`'s children, flattened.
    /// - Returns: The `OR`, its checks that an event is one of some types made one where the first was, or that
    ///   check alone when it's all the `OR` has.
    private static func joiningTypeChecks(_ children: [IndicatorDraft]) -> IndicatorDraft {
        var types: [Int] = [], first: Int?
        for (position, child) in children.enumerated() {
            guard case .eventType(let op, let checked) = child, op != .notEqualTo else { continue }
            types += checked
            first = first ?? position
        }
        guard let first, children.count > 1 else { return .or(children) }
        let unique = Array(Set(types)).sorted()
        let joined = IndicatorDraft.eventType(unique.count == 1 ? .equalTo : .in, unique)
        let rest = children.enumerated().compactMap { position, child -> IndicatorDraft? in
            if position == first { return joined }
            if case .eventType(let op, _) = child, op != .notEqualTo { return nil }
            return child
        }
        return rest.count == 1 ? rest[0] : .or(rest)
    }

    /// What reading a part's fields can cost an event, which orders an `AND`'s and an `OR`'s children
    /// (``readingCheapestFirst``).
    enum ReadCost: Int, CaseIterable, Comparable {
        /// Only fields that stay small, or none.
        case small
        /// `command_line`, `env` or `script_content`, which an event can make up to 1 MiB (``ScanPool/isLarge``): a
        /// search of one can spend its pool, and the index's, whole.
        case large
        /// A record field, which walks the event's encoding the first time one is read (``RecordPathTrie``).
        case record

        /// - Parameters:
        ///   - lhs: A cost.
        ///   - rhs: Another.
        /// - Returns: Is `lhs` the cheaper?
        static func < (lhs: ReadCost, rhs: ReadCost) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    /// What reading its fields can cost an event: the costliest of its comparisons'.
    var readCost: ReadCost {
        switch self {
        case .and(let children), .or(let children): children.map(\.readCost).max() ?? .small
        case .not(let child): child.readCost
        case .compare(let comparison): Self.readCost(of: comparison.field)
        case .compareFields(let comparison):
            Swift.max(Self.readCost(of: comparison.left), Self.readCost(of: comparison.right))
        case .truth, .eventType: .small
        }
    }

    /// - Parameter field: A field.
    /// - Returns: What reading it can cost an event.
    private static func readCost(of field: IndicatorField) -> ReadCost {
        !field.isDirect ? .record : field.scanPool.isLarge ? .large : .small
    }

    /// The same, with each `AND`'s and `OR`'s children ordered by what reading them can cost (``ReadCost``): those
    /// that read only small fields first, then those that read a large one, then those that read a record field. So a
    /// cheap child decides it first: a target's path rules out an exec before its 1 MiB command line is searched, and
    /// most events are never walked. On a cost tie, the index anchors an `AND` on its first cheapest child
    /// (``IndicatorProgram/View/necessity(root:eventType:)``), so a small field's literal is checked rather than a
    /// large one's. A verdict doesn't depend on its children's order (``IndicatorProgram/View``), so no verdict
    /// changes, save which comparison a spent scan budget refuses.
    var readingCheapestFirst: IndicatorDraft {
        /// - Parameter children: An `AND`'s or an `OR`'s children.
        /// - Returns: The same, each reordered within, by their cost and, at the same cost, in their order.
        func cheapestFirst(_ children: [IndicatorDraft]) -> [IndicatorDraft] {
            let ordered = children.map(\.readingCheapestFirst)
            return ReadCost.allCases.flatMap { cost in ordered.filter { $0.readCost == cost } }
        }
        return switch self {
        case .and(let children): .and(cheapestFirst(children))
        case .or(let children): .or(cheapestFirst(children))
        case .not(let child): .not(child.readingCheapestFirst)
        default: self
        }
    }

    /// The same, without the type checks every event it runs on passes: a top-level `AND`'s, or the whole rule's.
    /// One anywhere else stays.
    ///
    /// - Parameter types: The types the rule runs on.
    /// - Returns: The draft, `TRUEPREDICATE` when nothing's left.
    func removingTypeChecks(passedBy types: Set<Int>) -> IndicatorDraft {
        /// - Parameter draft: A part of the rule.
        /// - Returns: Is it a type check every event the rule runs on passes?
        func isPassed(_ draft: IndicatorDraft) -> Bool {
            guard case .eventType(let op, let checked) = draft, op != .notEqualTo else { return false }
            return types.isSubset(of: checked)
        }
        if isPassed(self) { return .truth(true) }
        guard case .and(let children) = self else { return self }
        let kept = children.filter { !isPassed($0) }
        return kept.isEmpty ? .truth(true) : kept.count == 1 ? kept[0] : .and(kept)
    }
}
