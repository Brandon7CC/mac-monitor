//
//  RelatedEvents.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Subqueries
/// A search predicate's `SUBQUERY`s of related events, and the events each collected.
///
/// Evaluating a `SUBQUERY` on every event, through every other, would take each event's record once per event. So
/// each `SUBQUERY` is split. Its conditions on the related event alone (`$e.es_event_type == …`), joined by `AND`,
/// pick the events it keeps, once each, as ``collect(_:)`` is given every event before any is searched. Its conditions
/// on both events join them, for each searched event, on the events kept in its group, looked up by an equality
/// (`$e.path == path`) when there is one. Not thread-safe: each ``StreamFilter/Predicate`` has its own.
final class RelatedEvents {
    /// The most related events one `SUBQUERY` keeps, about as many records as a search keeps in memory at once.
    static let limit = 20_000
    /// The most pairs of a searched and a related event one `SUBQUERY` compares in a search, a few seconds' worth:
    /// `NSPredicate` takes microseconds a pair. An equality's lookup compares only the events it finds.
    static let pairLimit = 250_000

    /// Why a `SUBQUERY` failed during the evaluation in progress, if one did.
    var failure: String?
    /// The predicate's `MATCHES`, rewritten for its `SUBQUERY`s' conditions too.
    private let matches: BoundedMatches
    private var subqueries: [Subquery] = []

    /// Does the predicate have a `SUBQUERY`?
    var isEmpty: Bool { subqueries.isEmpty }

    /// The events any `SUBQUERY` might keep, as the store can narrow them: `nil` when one can't be narrowed.
    var storePredicate: NSPredicate? {
        let narrowed = subqueries.compactMap(\.storePredicate)
        guard !narrowed.isEmpty, narrowed.count == subqueries.count else { return nil }
        return narrowed.count == 1 ? narrowed[0] : NSCompoundPredicate(orPredicateWithSubpredicates: narrowed)
    }

    /// - Parameter matches: The predicate's `MATCHES`.
    init(matches: BoundedMatches) {
        self.matches = matches
    }

    /// Replace each `SUBQUERY` in a predicate with its related events, and evaluate the rest first: `NSPredicate`
    /// evaluates `AND` and `OR` in order and stops once it knows, so `SUBQUERY(…) AND es_event_type == …` only
    /// goes through related events for the events of that type.
    ///
    /// - Parameters:
    ///   - predicate: A predicate ``PredicateGuard`` passed.
    ///   - audience: Who an error is for.
    /// - Returns: The predicate, its `SUBQUERY`s evaluated on the events ``collect(_:)`` kept.
    /// - Throws: ``CommandLineUsageError`` for a `MATCHES` pattern that isn't a regular expression.
    func rewrite(_ predicate: NSPredicate, for audience: PredicateAudience) throws -> NSPredicate {
        switch predicate {
        case let compound as NSCompoundPredicate:
            let subpredicates = compound.subpredicates.compactMap { $0 as? NSPredicate }
            let ordered = subpredicates.filter { !$0.contains(where: Self.isSubquery) }
                + subpredicates.filter { $0.contains(where: Self.isSubquery) }
            return NSCompoundPredicate(type: compound.compoundPredicateType,
                                       subpredicates: try ordered.map { try rewrite($0, for: audience) })
        case let comparison as NSComparisonPredicate where comparison.contains(where: Self.isSubquery):
            return NSComparisonPredicate(leftExpression: try rewrite(comparison.leftExpression, for: audience),
                                         rightExpression: try rewrite(comparison.rightExpression, for: audience),
                                         modifier: comparison.comparisonPredicateModifier,
                                         type: comparison.predicateOperatorType, options: comparison.options)
        default:
            return predicate
        }
    }

    /// - Parameters:
    ///   - expression: An expression ``PredicateGuard`` passed.
    ///   - audience: Who an error is for.
    /// - Returns: The expression, each `SUBQUERY` in it a block returning its related events.
    private func rewrite(_ expression: NSExpression, for audience: PredicateAudience) throws -> NSExpression {
        guard expression.contains(where: Self.isSubquery) else { return expression }
        switch expression.expressionType {
        case .subquery:
            let subquery = try Subquery(expression, matches: matches, for: audience)
            subqueries.append(subquery)
            return NSExpression(block: { [unowned self] object, _, _ in self.related(subquery, to: object) },
                                arguments: [])
        case .function:
            return NSExpression(forFunction: try rewrite(expression.operand, for: audience),
                                selectorName: expression.function,
                                arguments: try (expression.arguments ?? []).map { try rewrite($0, for: audience) })
        case .aggregate:
            let members = (expression.collection as? [NSExpression]) ?? []
            return NSExpression(forAggregate: try members.map { try rewrite($0, for: audience) })
        default:
            return expression
        }
    }

    /// Keep each event a `SUBQUERY` picks. Give it every event before evaluating the predicate on any.
    ///
    /// - Parameter record: An event's record.
    /// - Throws: ``PredicateFailure`` if a `SUBQUERY`'s conditions on the related event can't be evaluated on it.
    func collect(_ record: NSDictionary) throws {
        let related = PredicateRecord(record)
        for subquery in subqueries {
            matches.failure = nil
            try subquery.collect(related)
            if let failure = matches.failure { throw PredicateFailure(description: failure) }
        }
    }

    /// - Parameters:
    ///   - subquery: A `SUBQUERY`.
    ///   - object: The searched event.
    /// - Returns: Its related events that the `SUBQUERY` matches, none once anything failed.
    private func related(_ subquery: Subquery, to object: Any?) -> NSArray {
        guard failure == nil, let searched = object as? PredicateRecord else { return [] }
        do {
            return try subquery.matches(for: searched)
        } catch {
            failure = "\(error)"
            return []
        }
    }

    /// - Parameter expression: An expression.
    /// - Returns: Is it a `SUBQUERY`?
    private static func isSubquery(_ expression: NSExpression) -> Bool {
        expression.expressionType == .subquery
    }
}
