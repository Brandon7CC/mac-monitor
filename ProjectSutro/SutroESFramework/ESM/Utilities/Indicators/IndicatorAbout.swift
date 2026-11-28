//
//  IndicatorAbout.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - About an indicator
/// What Settings > Indicators says about one indicator besides what's edited there: its identity, where it comes
/// from, its revision and whether this Mac changed it, the event types it runs on, and the Mac Monitor it requires.
public struct IndicatorAbout: Equatable {
    /// One fact: its name, and its value.
    public struct Row: Equatable, Identifiable {
        public let name: String
        public let value: String
        public var id: String { name }
    }

    /// The indicator's identity, which every hit carries.
    public let identity: String
    /// The facts in a few words, for when they're folded away: `Pack 1, revision 2`, with `edited` after it for one
    /// this Mac changed, or `Added on this Mac`.
    public let summary: String
    /// The facts, in the order they're shown.
    public let rows: [Row]

    /// - Parameters:
    ///   - indicator: The indicator, as this Mac has it.
    ///   - baseline: The indicators Mac Monitor ships on this Mac: its pack's.
    ///   - pack: Which pack they are, or `nil` when the Security Extension hasn't said.
    public init(_ indicator: Indicator, baseline: [Indicator], pack: IndicatorPackStatus?) {
        identity = indicator.id.uuidString
        var rows = [Row(name: "ID", value: identity)]
        if let shipped = baseline.first(where: { $0.id == indicator.id }) {
            let isEdited = !indicator.sameIndicator(as: shipped)
            rows.append(Row(name: "Source", value: Self.source(of: pack)))
            if let revision = shipped.revision { rows.append(Row(name: "Revision", value: String(revision))) }
            rows.append(Row(name: "State", value: isEdited ? "Edited on this Mac" : "Unchanged"))
            summary = [(pack?.sequence ?? 0) > 0 ? "Pack \(pack?.sequence ?? 0)" : "Mac Monitor",
                       shipped.revision.map { "revision \($0)" }, isEdited ? "edited" : nil]
                .compactMap { $0 }.joined(separator: ", ")
        } else {
            rows.append(Row(name: "Source", value: "Added on this Mac"))
            summary = "Added on this Mac"
        }
        rows.append(Row(name: "Runs on", value: Self.eventTypes(of: indicator)))
        if let minEngine = indicator.minEngine {
            rows.append(Row(name: "Requires", value: "Mac Monitor \(minEngine) or later"))
        }
        self.rows = rows
    }

    /// - Parameter pack: Which pack Mac Monitor's indicators are.
    /// - Returns: Where a shipped indicator comes from: `Mac Monitor (Pack 1)`, or `Mac Monitor` for a build's own.
    private static func source(of pack: IndicatorPackStatus?) -> String {
        guard let pack, pack.sequence > 0 else { return "Mac Monitor" }
        return "Mac Monitor (Pack \(pack.sequence))"
    }

    /// - Parameter indicator: An indicator.
    /// - Returns: The event types its rule, or its sequence's steps, name, such as `close, rename`, in order.
    private static func eventTypes(of indicator: Indicator) -> String {
        let types = indicator.rule.predicates.reduce(into: Set<String>()) { types, rule in
            guard let parsed = try? StreamFilter.Predicate.parse(rule.predicate, for: .indicator) else { return }
            types.formUnion(PredicateEventTypes.eventTypes(of: parsed) ?? [])
        }
        let names = types.map { $0.hasPrefix(EventNames.notifyPrefix) ? EventNames.shortName($0) : $0 }.sorted()
        return names.isEmpty ? "No event type" : names.joined(separator: ", ")
    }
}
