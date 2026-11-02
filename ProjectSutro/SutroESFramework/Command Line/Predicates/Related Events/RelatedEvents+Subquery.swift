//
//  RelatedEvents+Subquery.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - One subquery
extension RelatedEvents {
    /// One `SUBQUERY(relation, $e, conditions)`, and the related events it kept.
    final class Subquery {
        let relation: PredicateRelation
        /// Its variable's name, `e` for `$e`.
        let variable: String
        /// Its conditions on the related event alone, which pick the events it keeps. `nil` keeps every one.
        private let picks: NSPredicate?
        /// What the store can narrow the events it might keep to, from its conditions on the related event alone:
        /// `nil` when nothing can be said, so every event is a candidate.
        let storePredicate: NSPredicate?
        /// Its conditions on both events. `nil` matches each event it kept.
        private let joins: NSPredicate?
        /// An equality in ``joins``, `$e.path == expression`, to look a searched event's related events up by.
        private let lookup: (path: String, searched: NSExpression)?
        /// The events kept, by ``PredicateRelation/group(ofRelated:)``.
        private var kept: [AnyHashable: [PredicateRecord]] = [:]
        private var count = 0
        /// The pairs of events compared so far, up to ``RelatedEvents/pairLimit``.
        private var compared = 0
        /// Did it pick more than ``RelatedEvents/limit``?
        private var overflowed = false
        /// The events kept by group and their ``lookup`` path's value, built on first use. `nil` once a value
        /// can't be looked up by, an array or an object: those are each compared instead.
        private lazy var index: [Pair: [PredicateRecord]]? = makeIndex()
        /// Which events each group kept are which event, to leave a searched event out of its own related events
        /// without comparing it with each: built for a group on first use, and dropped when the group keeps another.
        private var sameness: [AnyHashable: Sameness] = [:]

        /// A group and a value.
        private struct Pair: Hashable {
            let group: AnyHashable
            let value: AnyHashable
        }

        /// - Parameters:
        ///   - subquery: A `SUBQUERY` ``PredicateGuard`` passed.
        ///   - matches: The predicate's `MATCHES`.
        ///   - audience: Who an error is for.
        /// - Throws: ``CommandLineUsageError`` for a `MATCHES` pattern that isn't a regular expression.
        init(_ subquery: NSExpression, matches: BoundedMatches, for audience: PredicateAudience) throws {
            guard let collection = subquery.collection as? NSExpression,
                  let relation = PredicateRelation(rawValue: collection.keyPath) else {
                throw CommandLineUsageError("\(audience.name) can't use \(subquery.description).",
                                            command: audience.command)
            }
            self.relation = relation
            variable = subquery.variable
            let conditions = subquery.predicate
            let conjuncts = (conditions as? NSCompoundPredicate)?.compoundPredicateType == .and
                ? (conditions as! NSCompoundPredicate).subpredicates.compactMap { $0 as? NSPredicate } : [conditions]
            let joining = conjuncts.filter(Self.readsSearched), picking = conjuncts.filter { !Self.readsSearched($0) }
            /// The conditions joined by `AND`, or `nil` for none.
            func and(_ predicates: [NSPredicate]) -> NSPredicate? {
                predicates.count > 1 ? NSCompoundPredicate(andPredicateWithSubpredicates: predicates) : predicates.first
            }
            let picked = and(picking)
            picks = try picked.map { try matches.rewrite($0, for: audience) }
            storePredicate = picked.flatMap { [variable] in StoreNarrowing.predicate(for: $0, variable: variable) }
            joins = try and(joining).map { try matches.rewrite($0, for: audience) }
            lookup = joining.lazy.compactMap { [variable] in Self.lookup(in: $0, variable) }.first
        }

        /// Keep an event if the conditions on the related event alone pick it.
        ///
        /// - Parameter related: The event's record.
        /// - Throws: Why the conditions couldn't be evaluated on it.
        func collect(_ related: PredicateRecord) throws {
            guard !overflowed, let group = relation.group(ofRelated: related.values) else { return }
            if let picks, try !PredicateBridge.evaluate(picks, with: related, variables: [variable: related]) { return }
            guard count < RelatedEvents.limit else {
                overflowed = true
                (kept, sameness) = ([:], [:])
                return
            }
            kept[group, default: []].append(related)
            sameness[group] = nil
            count += 1
        }

        /// - Parameter searched: The searched event.
        /// - Returns: Its related events that the conditions on both events match.
        /// - Throws: ``PredicateFailure`` once the `SUBQUERY` kept too many events or compared too many pairs, or why
        ///   the conditions couldn't be evaluated.
        func matches(for searched: PredicateRecord) throws -> NSArray {
            guard !overflowed else {
                throw PredicateFailure(description: """
                    SUBQUERY(\(relation.rawValue), $\(variable), …) picks more than \(RelatedEvents.limit) related \
                    events: narrow it with conditions on $\(variable) alone, joined by AND.
                    """)
            }
            guard let group = relation.group(ofSearched: searched.values), var related = kept[group] else {
                return NSArray()
            }
            if let lookup, let index, let value = try PredicateRelation.hashable(
                PredicateBridge.evaluate(lookup.searched, with: searched, variables: nil)) {
                related = index[Pair(group: group, value: value)] ?? []
            }
            guard let joins else { return excluding(searched, from: related, in: group) }
            compared += related.count
            guard compared <= RelatedEvents.pairLimit else {
                throw PredicateFailure(description: """
                    SUBQUERY(\(relation.rawValue), $\(variable), …) compares more than \
                    \(RelatedEvents.pairLimit.formatted()) pairs of events: narrow it with conditions on $\(variable) \
                    alone, or join on an equality, such as $\(variable).process.pid == process.pid.
                    """)
            }
            /// The searched event itself is left out after, from the few the conditions match.
            return try PredicateBridge.filter(related, with: joins, object: searched, variable: variable)
                .compactMap { $0 as? PredicateRecord }.filter { !$0.isSame(as: searched) } as NSArray
        }
        
        /// A group's events without the searched event itself (and any copy of it), in their order: the group's
        /// array, or a view of it that skips those, never a copy. Filtering every one per searched event cost about
        /// 10 ms with 20,000 kept.
        ///
        /// - Parameters:
        ///   - searched: The searched event.
        ///   - related: The group's events.
        ///   - group: The group.
        /// - Returns: Its related events.
        private func excluding(_ searched: PredicateRecord, from related: [PredicateRecord],
                               in group: AnyHashable) -> NSArray {
            let same = sameness[group] ?? Sameness(related)
            sameness[group] = same
            let skipped = same.indexes(of: searched)
            return skipped.isEmpty ? related as NSArray : SkippingArray(related, skipping: skipped)
        }

        /// - Returns: The events kept by group and ``lookup`` value, or `nil` if a value can't be looked up by.
        private func makeIndex() -> [Pair: [PredicateRecord]]? {
            guard let lookup else { return nil }
            var index: [Pair: [PredicateRecord]] = [:]
            for (group, records) in kept {
                for record in records {
                    guard let value = record.value(forKeyPath: lookup.path), !(value is NSNull) else { continue }
                    guard let value = PredicateRelation.hashable(value) else { return nil }
                    index[Pair(group: group, value: value), default: []].append(record)
                }
            }
            return index
        }

        /// - Parameters:
        ///   - predicate: One of the conditions on both events.
        ///   - variable: The variable's name.
        /// - Returns: `path` and `expression` for `$e.path == expression`, or the same the other way round.
        private static func lookup(in predicate: NSPredicate, _ variable: String) -> (String, NSExpression)? {
            guard let comparison = predicate as? NSComparisonPredicate, comparison.predicateOperatorType == .equalTo,
                  comparison.comparisonPredicateModifier == .direct, comparison.options.isEmpty else { return nil }
            for (related, searched) in [(comparison.leftExpression, comparison.rightExpression),
                                        (comparison.rightExpression, comparison.leftExpression)] {
                if let path = related.keyPath(of: variable),
                   !searched.contains(where: { $0.expressionType == .variable }) { return (path, searched) }
            }
            return nil
        }

        /// - Parameter predicate: One of a `SUBQUERY`'s conditions.
        /// - Returns: Does it read the searched event, with a plain key path or `SELF`?
        private static func readsSearched(_ predicate: NSPredicate) -> Bool {
            predicate.contains { $0.expressionType == .keyPath || $0.expressionType == .evaluatedObject }
        }
    }
}
