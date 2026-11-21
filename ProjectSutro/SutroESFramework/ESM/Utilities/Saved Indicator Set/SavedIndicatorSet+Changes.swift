//
//  SavedIndicatorSet+Changes.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/16/26.
//

import Foundation


// MARK: - The set a request asks for
extension SavedIndicatorSet {
    /// The set a request asks for. Every indicator it brings is checked first (``IndicatorFile/validateIncoming(_:)``).
    ///
    /// - Parameter request: The request.
    /// - Returns: The next set, in order.
    /// - Throws: ``IndicatorFileError``, or ``IndicatorRequestProblem`` for an identity the set doesn't have.
    func nextIndicators(for request: IndicatorRequest) throws -> [Indicator] {
        let indicators = saved.indicators
        switch request.operation {
        case .list, .checkPack, .installPack, .setPackMode:
            return indicators
        case .add:
            try IndicatorFile.validateIncoming(request.indicators)
            return IndicatorExchange.merge(request.indicators, into: indicators).indicators
        case .replace:
            try IndicatorFile.validateIncoming(request.indicators)
            return request.indicators
        case .reset:
            return defaults
        case .remove:
            try checkKnown(request.ids)
            let removing = Set(request.ids)
            return indicators.filter { !removing.contains($0.id) }
        case .setEnabled:
            guard let enabled = request.enabled else {
                throw IndicatorRequestProblem("Say whether to turn the indicators on or off.")
            }
            try checkKnown(request.ids)
            let changing = Set(request.ids)
            return indicators.map { indicator in
                var indicator = indicator
                if changing.contains(indicator.id) { indicator.isEnabled = enabled }
                return indicator
            }
        case .update:
            return try updated(indicators, by: request)
        }
    }

    /// The set after an update: the named fields of each indicator the request brings taken into the one with its
    /// identity, in its place, and nothing else changed. What it makes is checked as the indicators an add brings
    /// are.
    ///
    /// - Parameters:
    ///   - indicators: The set now.
    ///   - request: The update.
    /// - Returns: The next set, in order.
    /// - Throws: ``IndicatorRequestProblem`` for no fields, an identity named twice or one the set doesn't have.
    ///   ``IndicatorFileError`` for an indicator the update leaves past a limit.
    func updated(_ indicators: [Indicator], by request: IndicatorRequest) throws -> [Indicator] {
        guard !request.fields.isEmpty else { throw IndicatorRequestProblem("Name the fields to change.") }
        let ids = request.indicators.map(\.id)
        guard Set(ids).count == ids.count else { throw IndicatorRequestProblem("Name each indicator once.") }
        try checkKnown(ids)
        let incoming = Dictionary(uniqueKeysWithValues: request.indicators.map { ($0.id, $0) })
        let next = indicators.map { indicator in
            guard let edit = incoming[indicator.id] else { return indicator }
            var indicator = indicator
            indicator.take(request.fields, from: edit)
            return indicator
        }
        try IndicatorFile.validateIncoming(next.filter { incoming[$0.id] != nil })
        return next
    }

    /// - Parameter ids: Identities a request names.
    /// - Throws: ``IndicatorRequestProblem`` when it names none, or one the set doesn't have.
    func checkKnown(_ ids: [UUID]) throws {
        guard !ids.isEmpty else { throw IndicatorRequestProblem("Name the indicators by their identities.") }
        let known = Set(saved.indicators.map(\.id))
        let unknown = ids.filter { !known.contains($0) }
        guard unknown.isEmpty else {
            let list = unknown.map(\.uuidString).joined(separator: ", ")
            throw IndicatorRequestProblem("No indicator has the identity \(list).")
        }
    }
}


// MARK: - Request problems
/// Why a request can't be done, beyond what ``IndicatorFileError`` says: such as an identity the set doesn't have.
struct IndicatorRequestProblem: Error, CustomStringConvertible {
    /// The problem, as a sentence.
    let description: String

    /// - Parameter description: The problem, as a sentence.
    init(_ description: String) {
        self.description = description
    }
}
