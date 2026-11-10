//
//  StreamFilter+Indicators.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Filtering by the indicators a record lists
public extension StreamFilter.Predicate {
    /// A predicate that matches the events whose records list any of these indicators: `ANY indicators.id IN {...}`.
    /// It's the Filters sheet's indicator filter, so it gives an event the answer its dots, a search and its record do:
    /// the Security Extension's stored verdicts when it has them, else the indicators matched now
    /// (``searching(indicators:_:)``).
    ///
    /// - Parameters:
    ///   - ids: The indicators' identities. There may be any number.
    ///   - audience: Who its errors are for.
    /// - Returns: The predicate, or `nil` for no identities.
    static func listing(_ ids: [UUID], for audience: PredicateAudience) -> StreamFilter.Predicate? {
        guard !ids.isEmpty else { return nil }
        let constants = ids.map { "\"\($0.uuidString)\"" }.joined(separator: ", ")
        return try? StreamFilter.Predicate("ANY indicators.id IN {\(constants)}", for: audience, maxLength: .max)
    }

    /// What the store can narrow the events to, as ``storePredicate`` says, and for a predicate that names
    /// `indicators` or `indicators_undetermined`, what it can say of the indicators their records list
    /// (``IndicatorNarrowing``).
    ///
    /// - Parameter indicators: The indicators the records list for events without stored verdicts, as
    ///   ``searching(indicators:_:)`` is given them. Read only when the predicate names `indicators`.
    /// - Returns: A predicate on the store's columns, or `nil` when none can be said.
    func storePredicate(listing indicators: @autoclosure () -> [Indicator]) -> NSPredicate? {
        guard readsIndicators else { return storePredicate }
        let narrowing = IndicatorNarrowing(readsIndicatorHits ? indicators() : [])
        return StoreNarrowing.predicate(for: parsed, indicators: narrowing)
    }
}


// MARK: - Narrowing by stored verdicts
/// What the store can say of `ANY indicators.id IN {...}`, or `ANY indicators.id == "..."`: an event's record lists
/// one of those indicators only when its stored verdicts hold a hit (``ESMessage/indicatorsData`` is neither `nil`
/// nor `[]`), or when it has none and one of them, on now, could match it, as its own predicate narrows the store.
/// And of any `ANY indicators_undetermined...` comparison: only an event that stores undetermined indicators
/// (``ESMessage/indicatorsUndeterminedData``) lists any, so that's exact.
///
/// Live events from a Security Extension that stamps every event are mostly `[]`, so only those with a hit are read.
/// An Open Trace, or events from an older Security Extension, are narrowed as each named indicator's predicate is.
struct IndicatorNarrowing {
    /// What the store narrows the events each indicator that's on and usable could match to, by identity: `nil`
    /// when it can't narrow them. An indicator off, or whose predicate can't be used, matches no event now.
    private let local: [UUID: NSPredicate?]

    /// - Parameter indicators: The indicators records list for events without stored verdicts.
    init(_ indicators: [Indicator]) {
        let pairs = indicators.filter(\.isEnabled).compactMap { indicator -> (UUID, NSPredicate?)? in
            (try? StreamFilter.Predicate(indicator.predicate, for: .indicator))
                .map { (indicator.id, $0.storePredicate) }
        }
        local = Dictionary(pairs) { first, _ in first }
    }

    /// The events whose records list undetermined indicators.
    private static let undetermined = NSPredicate(format: "indicatorsUndeterminedData != nil")

    /// - Parameter comparison: A comparison in the predicate, outside any `SUBQUERY`.
    /// - Returns: The events whose records may list one of the indicators it names, or `nil` when it neither
    ///   compares `indicators.id` with constant identities nor compares any of `indicators_undetermined`.
    func narrowed(_ comparison: NSComparisonPredicate) -> NSPredicate? {
        guard comparison.comparisonPredicateModifier == .any,
              comparison.leftExpression.expressionType == .keyPath else { return nil }
        let path = comparison.leftExpression.keyPath
        if path == "indicators_undetermined" || path.hasPrefix("indicators_undetermined.") { return Self.undetermined }
        guard path == "indicators.id", let ids = Self.identities(in: comparison) else { return nil }
        let named = ids.compactMap { local[$0] }
        let unstamped: NSPredicate = named.isEmpty ? NSPredicate(value: false)
            : named.contains { $0 == nil } ? NSPredicate(value: true)
            : NSCompoundPredicate(orPredicateWithSubpredicates: named.compactMap { $0 })
        return NSCompoundPredicate(orPredicateWithSubpredicates: [
            NSPredicate(format: "indicatorsData != nil AND indicatorsData != %@", ESMessage.noHits as NSData),
            NSCompoundPredicate(andPredicateWithSubpredicates: [NSPredicate(format: "indicatorsData == nil"),
                                                                unstamped]),
        ])
    }

    /// - Parameter comparison: A comparison on `indicators.id`.
    /// - Returns: The identities `==` or `IN` compares with, or `nil` for another comparison or a value that isn't
    ///   a constant identity.
    private static func identities(in comparison: NSComparisonPredicate) -> [UUID]? {
        let right = comparison.rightExpression
        let constants: [Any]
        switch (comparison.predicateOperatorType, right.expressionType) {
        case (.equalTo, .constantValue):
            constants = [right.constantValue as Any]
        case (.in, .aggregate):
            let members = (right.collection as? [NSExpression]) ?? []
            guard members.allSatisfy({ $0.expressionType == .constantValue }) else { return nil }
            constants = members.map { $0.constantValue as Any }
        case (.in, .constantValue):
            switch right.constantValue {
            case let array as NSArray: constants = array as [AnyObject]
            case let set as NSSet: constants = set.allObjects
            default: return nil
            }
        default:
            return nil
        }
        let ids = constants.compactMap { ($0 as? String).flatMap(UUID.init(uuidString:)) }
        return ids.count == constants.count ? ids : nil
    }
}
