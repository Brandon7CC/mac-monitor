//
//  IndicatorFilter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Indicator filter
/// The event tables' indicator filter as the main window keeps it: Any indicator, which shows only the events of the
/// indicators that are on and mark the tables (``IndicatorSelection/any``), and its predicate as the indicators are
/// now. Every control that shows it reads it from here, so wherever it says the tables show only those events it can be
/// switched off: the Filters sheet's indicator card, whose switch it is, and the predicate editor's footer.
public struct IndicatorFilter: Equatable {
    /// What it's called.
    public static let name = "Any indicator"

    /// Is it on, filtering or dropped? It stays on when it's dropped, so it can be switched off.
    public private(set) var isOn = false
    /// Its predicate, from the indicators as they are now. It's `nil` when it's off, and when it's dropped because no
    /// indicator it filters by is offered.
    public private(set) var predicate: StreamFilter.Predicate?

    /// A filter that's off.
    public init() {}

    /// Is it on but filtering nothing, because no indicator it filters by is offered?
    public var isDropped: Bool { isOn && predicate == nil }

    /// Its name while it filters the tables, or `nil` when it's off or dropped.
    public var filtering: String? { predicate == nil ? nil : Self.name }

    /// The filter switched on or off, read from the indicators as they are now.
    ///
    /// - Parameters:
    ///   - isOn: Should it show only the indicators' events?
    ///   - offered: The indicators offered, as ``IndicatorSelection/offered(_:)`` picks them.
    ///   - audience: Who the predicate is for.
    /// - Returns: The filter.
    public func switched(_ isOn: Bool, offered: [Indicator], for audience: PredicateAudience) -> IndicatorFilter {
        var next = IndicatorFilter()
        next.isOn = isOn
        next.predicate = isOn ? IndicatorSelection.any.predicate(offered: offered, for: audience) : nil
        return next
    }

    /// Why it can't filter by these indicators: it filters by those offered that mark the tables, as its predicate
    /// does.
    ///
    /// - Parameter offered: The indicators offered, as ``IndicatorSelection/offered(_:)`` picks them.
    /// - Returns: The reason, or `nil` when one it filters by is offered.
    public static func unavailableReason(offered: [Indicator]) -> String? {
        if offered.isEmpty { return "No indicator is on" }
        return offered.contains { !$0.tableMarks.isEmpty } ? nil : "No indicator that's on marks the event tables"
    }

    /// What the Filters sheet's indicator card says it does, or why it's dropped.
    ///
    /// - Parameter offered: The indicators offered, as ``IndicatorSelection/offered(_:)`` picks them.
    /// - Returns: The card's explanation.
    public func about(offered: [Indicator]) -> String {
        if isDropped {
            let reason = Self.unavailableReason(offered: offered) ?? "The indicators' predicates can't be used"
            return "\(reason), so events aren't filtered. Switch it off"
        }
        return "Show only the events of the indicators that are on and mark the event tables. Settings > Indicators "
            + "sets what each finds and how it marks them"
    }
}
