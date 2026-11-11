//
//  IndicatorScopeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Settings > Indicators' list
/// Pins Settings > Indicators' list and sections as Subscriptions draws its own: the rows in their groups, their
/// counts, a search that shows every indicator it finds whatever was picked, and the cards each row shows.
final class IndicatorScopeTests: XCTestCase {
    /// Two persistence indicators, one off and one whose symbol marks the tables, an execution one, and one with no
    /// tactic.
    private var indicators: [Indicator] {
        [Self.indicator("Launch agent", tactic: .persistence, tables: [.dot, .symbol]),
         Self.indicator("Cron job", tactic: .persistence, isEnabled: false),
         Self.indicator("Ran a script", tactic: .execution),
         Self.indicator("Loose end", tactic: nil)]
    }

    /// - Parameters:
    ///   - name: Its name.
    ///   - tactic: Its tactic, or `nil`.
    ///   - tables: How it marks the tables.
    ///   - isEnabled: Is it on?
    /// - Returns: An indicator.
    private static func indicator(_ name: String, tactic: Indicator.Tactic?, tables: Indicator.TableMarks = .dot,
                                  isEnabled: Bool = true) -> Indicator {
        Indicator(name: name, description: "", symbol: "star", color: .blue, predicate: "process.pid == 1",
                  tables: tables, isEnabled: isEnabled, tactic: tactic)
    }

    /// The rows come in three groups: All, the tactics that have an indicator in ATT&CK's order, then No Tactic only
    /// when one has none, Off and Symbol in Tables. A group with no rows is left out.
    func testRowsComeInGroups() {
        XCTAssertEqual(IndicatorScope.groups(for: indicators),
                       [[.all], [.tactic(.execution), .tactic(.persistence)], [.noTactic, .off, .symbol]])
        XCTAssertEqual(IndicatorScope.groups(for: Array(indicators.prefix(3))),
                       [[.all], [.tactic(.execution), .tactic(.persistence)], [.off, .symbol]])
        XCTAssertEqual(IndicatorScope.groups(for: []), [[.all], [.off, .symbol]])
    }

    /// While searching, the list keeps All and only the rows with an indicator found, dropping groups left empty.
    /// Spaces alone aren't a search.
    func testSearchKeepsOnlyRowsWithAMatch() {
        XCTAssertEqual(IndicatorScope.groups(for: indicators, search: "cron"),
                       [[.all], [.tactic(.persistence)], [.off]])
        XCTAssertEqual(IndicatorScope.groups(for: indicators, search: "nothing like it"), [[.all]])
        XCTAssertEqual(IndicatorScope.groups(for: indicators, search: "  "), IndicatorScope.groups(for: indicators))
    }

    /// A row counts how many are on of how many it has, as Subscriptions' classes do, Off how many it has, and while
    /// searching every row counts how many the search finds.
    func testCounts() {
        XCTAssertEqual(IndicatorScope.all.count(of: indicators), "3/4")
        XCTAssertEqual(IndicatorScope.tactic(.persistence).count(of: indicators), "1/2")
        XCTAssertEqual(IndicatorScope.noTactic.count(of: indicators), "1/1")
        XCTAssertEqual(IndicatorScope.symbol.count(of: indicators), "1/1")
        XCTAssertEqual(IndicatorScope.off.count(of: indicators), "1")
        XCTAssertEqual(IndicatorScope.all.count(of: indicators, search: "launch"), "1")
        XCTAssertEqual(IndicatorScope.tactic(.execution).count(of: indicators, search: "launch"), "0")
    }

    /// A search shows every indicator it finds, whatever row was picked, and no row is highlighted meanwhile.
    func testSearchShowsEveryRowAndHighlightsNone() {
        let picked = IndicatorScope.tactic(.execution)
        XCTAssertEqual(picked.shown(search: ""), picked)
        XCTAssertEqual(picked.shown(search: "cron"), .all)
        XCTAssertTrue(picked.highlights(picked, search: ""))
        XCTAssertFalse(picked.highlights(.all, search: ""))
        XCTAssertFalse(picked.highlights(picked, search: "cron"))
        XCTAssertEqual(picked.tactic, .execution)
        XCTAssertNil(IndicatorScope.off.tactic)
    }

    /// Each card is a tactic's indicators in ATT&CK's order, then those with none, with how many are on and whether
    /// Turn All switches them off.
    func testCardsByTactic() {
        let cards = IndicatorCard.cards(of: indicators, in: .all)
        XCTAssertEqual(cards.map(\.title), ["Execution", "Persistence", "No Tactic"])
        XCTAssertEqual(cards.map(\.summary), ["1 of 1 on", "1 of 2 on", "1 of 1 on"])
        XCTAssertEqual(cards.map(\.allOn), [true, false, true])
        XCTAssertEqual(cards.map(\.id), ["execution", "persistence", "none"])
    }

    /// A row's cards hold only its indicators. A search finds among them all, whatever row was picked, and the
    /// sections say why there are none.
    func testCardsFollowTheRowAndTheSearch() {
        let off = IndicatorCard.cards(of: indicators, in: .off)
        XCTAssertEqual(off.map(\.title), ["Persistence"])
        XCTAssertEqual(off.flatMap(\.indicators).map(\.name), ["Cron job"])
        XCTAssertNil(IndicatorCard.emptyText(off, in: .off, search: ""))
        let found = IndicatorCard.cards(of: indicators, in: .off, search: "script")
        XCTAssertEqual(found.flatMap(\.indicators).map(\.name), ["Ran a script"])
        let none = IndicatorCard.cards(of: indicators, in: .all, search: "nothing like it")
        XCTAssertEqual(IndicatorCard.emptyText(none, in: .off, search: "nothing like it"), "No indicators match.")
        XCTAssertEqual(IndicatorCard.emptyText(IndicatorCard.cards(of: [], in: .all), in: .all, search: ""),
                       "No indicators.")
    }

    /// Off and Symbol in Tables are always listed, so when nothing is off, or nothing draws its symbol, the sections
    /// say so rather than that there are no indicators.
    func testEmptyOffAndSymbolRowsSayWhy() {
        let allOn = [Self.indicator("Ran a script", tactic: .execution), Self.indicator("Loose end", tactic: nil)]
        let off = IndicatorCard.cards(of: allOn, in: .off)
        XCTAssertTrue(off.isEmpty)
        XCTAssertEqual(IndicatorCard.emptyText(off, in: .off, search: ""), "No indicators are off.")
        let symbol = IndicatorCard.cards(of: allOn, in: .symbol)
        XCTAssertTrue(symbol.isEmpty)
        XCTAssertEqual(IndicatorCard.emptyText(symbol, in: .symbol, search: ""),
                       "No indicator draws its symbol in the tables.")
        XCTAssertEqual(IndicatorCard.emptyText([], in: .tactic(.persistence), search: ""),
                       "No indicators in Persistence.")
        XCTAssertEqual(IndicatorCard.emptyText([], in: .noTactic, search: ""), "Every indicator has a tactic.")
    }

    /// A header counts every one of its tactic's indicators, as Subscriptions' header counts a class's every event,
    /// so the number doesn't change with the row picked or the search. Its cards still show only those picked.
    func testHeaderCountsTheWholeTactic() {
        for (scope, search) in [(IndicatorScope.off, ""), (.symbol, ""), (.all, "cron"), (.all, "launch")] {
            let cards = IndicatorCard.cards(of: indicators, in: scope, search: search)
            XCTAssertEqual(cards.map(\.title), ["Persistence"], "\(scope) \(search)")
            XCTAssertEqual(cards.map(\.indicators.count), [1], "\(scope) \(search)")
            XCTAssertEqual(cards.map(\.summary), ["1 of 2 on"], "\(scope) \(search)")
            XCTAssertEqual(cards.map(\.allOn), [false], "\(scope) \(search)")
            XCTAssertEqual(cards.flatMap(\.whole).map(\.name), ["Launch agent", "Cron job"], "\(scope) \(search)")
        }
    }
}
