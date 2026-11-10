//
//  IndicatorScope.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Settings > Indicators' list
/// What Settings > Indicators' list of classes picks, as Settings > Subscriptions' list picks a class of events:
/// every indicator, one tactic's, or those with no tactic, off, or whose symbol marks the tables. A search shows every
/// indicator it finds, whatever was picked, and the list shows only the rows with one.
public enum IndicatorScope: Hashable {
    /// Every indicator, a card for each tactic.
    case all
    /// One tactic's.
    case tactic(Indicator.Tactic)
    /// Those with no tactic.
    case noTactic
    /// Those switched off.
    case off
    /// Those whose symbol marks the event tables.
    case symbol

    /// The list's rows, in the groups it divides: every indicator; the tactics that have one, in ATT&CK's order; then
    /// those with no tactic if there are any, those off and those whose symbol marks the tables. While searching, only
    /// All and the rows with an indicator the search finds.
    ///
    /// - Parameters:
    ///   - indicators: Every indicator.
    ///   - search: What's typed in the search field, or "".
    /// - Returns: The groups of rows, none empty.
    public static func groups(for indicators: [Indicator], search: String = "") -> [[IndicatorScope]] {
        let tactics = Set(indicators.compactMap(\.tactic))
        let none = indicators.contains { $0.tactic == nil }
        let groups: [[IndicatorScope]] = [[.all], Indicator.Tactic.allCases.filter(tactics.contains).map(Self.tactic),
                                          (none ? [.noTactic] : []) + [.off, .symbol]]
        let found = indicators.filter { $0.matches(search: search) }
        let listed = isSearch(search) ? groups.map { $0.filter { $0 == .all || found.contains(where: $0.contains) } }
            : groups
        return listed.filter { !$0.isEmpty }
    }

    /// Its tactic, if it's a tactic's row.
    public var tactic: Indicator.Tactic? {
        if case .tactic(let tactic) = self { return tactic }
        return nil
    }

    /// Its row's name.
    public var title: String {
        switch self {
        case .all: return "All Indicators"
        case .tactic(let tactic): return tactic.name
        case .noTactic: return "No Tactic"
        case .off: return "Off"
        case .symbol: return "Symbol in Tables"
        }
    }

    /// - Parameter indicator: An indicator.
    /// - Returns: Is it among those this row shows?
    public func contains(_ indicator: Indicator) -> Bool {
        switch self {
        case .all: return true
        case .tactic(let tactic): return indicator.tactic == tactic
        case .noTactic: return indicator.tactic == nil
        case .off: return !indicator.isEnabled
        case .symbol: return indicator.tableMarks.contains(.symbol)
        }
    }

    /// Its row's count, as Subscriptions counts a class: how many are on of how many it has, or, for Off, how many
    /// it has. While searching, how many the search finds.
    ///
    /// - Parameters:
    ///   - indicators: Every indicator.
    ///   - search: What's typed in the search field, or "".
    /// - Returns: The count, such as `3/5`.
    public func count(of indicators: [Indicator], search: String = "") -> String {
        let mine = indicators.filter(contains)
        if Self.isSearch(search) { return "\(mine.filter { $0.matches(search: search) }.count)" }
        return self == .off ? "\(mine.count)" : "\(mine.filter(\.isEnabled).count)/\(mine.count)"
    }

    /// What the cards show: the row picked, or every indicator while searching.
    ///
    /// - Parameter search: What's typed in the search field, or "".
    /// - Returns: The row whose indicators the cards show.
    public func shown(search: String) -> IndicatorScope {
        Self.isSearch(search) ? .all : self
    }

    /// Is the row picked in the list highlighted? Not while searching, which shows every indicator it finds.
    ///
    /// - Parameters:
    ///   - row: A row of the list.
    ///   - search: What's typed in the search field, or "".
    /// - Returns: `true` when it's this row and nothing is searched for.
    public func highlights(_ row: IndicatorScope, search: String) -> Bool {
        row == self && !Self.isSearch(search)
    }

    /// - Parameter search: What's typed in the search field.
    /// - Returns: Is anything but spaces typed?
    static func isSearch(_ search: String) -> Bool {
        search.contains { !$0.isWhitespace }
    }
}


// MARK: - Cards
/// A section of Settings > Indicators: a tactic's indicators, or those with none, as the row picked shows them. Its
/// header counts and turns on or off every one of the tactic's, as Subscriptions' header does a class's events,
/// whatever the row and the search show.
public struct IndicatorCard: Identifiable {
    /// Its tactic, or `nil` for those with none.
    public let tactic: Indicator.Tactic?
    /// The indicators it shows.
    public let indicators: [Indicator]
    /// Every one of the tactic's indicators, which its header counts and Turn All changes.
    public let whole: [Indicator]

    public var id: String { tactic?.rawValue ?? "none" }
    /// Its header's name.
    public var title: String { tactic?.name ?? "No Tactic" }
    /// How many of the tactic's indicators are on.
    public var on: Int { whole.filter(\.isEnabled).count }
    /// Is every one of the tactic's indicators on, so Turn All switches them off?
    public var allOn: Bool { on == whole.count }
    /// Its header's count, such as "3 of 5 on".
    public var summary: String { "\(on) of \(whole.count) on" }

    /// The cards shown.
    ///
    /// - Parameters:
    ///   - indicators: Every indicator, in order.
    ///   - scope: The row picked in the list.
    ///   - search: What's typed in the search field, or "".
    /// - Returns: A card for each tactic with indicators the row and the search show, in ATT&CK's order, then one for
    ///   those with none.
    public static func cards(of indicators: [Indicator], in scope: IndicatorScope,
                             search: String = "") -> [IndicatorCard] {
        let scope = scope.shown(search: search)
        let shown = indicators.filter { scope.contains($0) && $0.matches(search: search) }
        let tactics: [Indicator.Tactic?] = Indicator.Tactic.allCases + [nil]
        return tactics.compactMap { tactic in
            let card = IndicatorCard(tactic: tactic, indicators: shown.filter { $0.tactic == tactic },
                                     whole: indicators.filter { $0.tactic == tactic })
            return card.indicators.isEmpty ? nil : card
        }
    }

    /// What the sections say when there are no cards.
    ///
    /// - Parameters:
    ///   - cards: The cards shown.
    ///   - scope: The row picked in the list.
    ///   - search: What's typed in the search field, or "".
    /// - Returns: Why there are none, or `nil` when there are cards.
    public static func emptyText(_ cards: [IndicatorCard], in scope: IndicatorScope, search: String) -> String? {
        guard cards.isEmpty else { return nil }
        if IndicatorScope.isSearch(search) { return "No indicators match." }
        switch scope {
        case .off: return "No indicators are off."
        case .symbol: return "No indicator draws its symbol in the tables."
        case .tactic(let tactic): return "No indicators in \(tactic.name)."
        case .noTactic: return "Every indicator has a tactic."
        case .all: return "No indicators."
        }
    }
}
