//
//  IndicatorFilterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Indicator filter
/// Pins the main window's indicator filter as its controls show it: Any indicator filters by the indicators that are on
/// and mark the tables, and switches off. It stays on when it's dropped, and says why, the reason the Filters sheet's
/// switch can't be turned on, so it can still be switched off.
final class IndicatorFilterTests: XCTestCase {
    /// The defaults, every one offered.
    private let offered = IndicatorSelection.offered(Indicator.defaults)

    /// - Parameters:
    ///   - isOn: Should it show only the indicators' events?
    ///   - offered: The indicators offered.
    ///   - filter: The filter it's switched from.
    /// - Returns: The filter switched.
    private func switched(_ isOn: Bool, _ offered: [Indicator],
                          from filter: IndicatorFilter = IndicatorFilter()) -> IndicatorFilter {
        filter.switched(isOn, offered: offered, for: .search)
    }

    /// A filter that's off filters nothing and says what it would show.
    func testOffFiltersNothing() {
        let off = IndicatorFilter()
        XCTAssertFalse(off.isOn)
        XCTAssertFalse(off.isDropped)
        XCTAssertNil(off.filtering)
        XCTAssertNil(off.predicate)
        XCTAssertEqual(off.about(offered: offered), "Show only the events of the indicators that are on and mark the "
                       + "event tables. Settings > Indicators sets what each finds and how it marks them")
        XCTAssertNil(IndicatorFilter.unavailableReason(offered: offered))
    }

    /// Any indicator filters by every offered indicator that marks the tables, goes by its own name, and switches off.
    func testAnyIndicatorFiltersByEveryOfferedIndicatorAndSwitchesOff() {
        let any = switched(true, offered)
        XCTAssertTrue(any.isOn)
        XCTAssertFalse(any.isDropped)
        XCTAssertEqual(any.filtering, IndicatorFilter.name)
        XCTAssertEqual(any.predicate, IndicatorSelection.any.predicate(offered: offered, for: .search))
        XCTAssertNotNil(any.predicate)
        XCTAssertEqual(switched(false, offered, from: any), IndicatorFilter())
    }

    /// A filter no offered indicator marks the tables for stays on, filters nothing, and says why, as the switch
    /// does before it's on: none on, or none on that marks the tables.
    func testDroppedStaysOnAndSaysWhy() {
        let unmarked = offered.map { indicator -> Indicator in
            var indicator = indicator
            indicator.tableMarks = []
            return indicator
        }
        let cases: [([Indicator], String)] = [
            ([], "No indicator is on"),
            (unmarked, "No indicator that's on marks the event tables"),
        ]
        for (changed, reason) in cases {
            XCTAssertEqual(IndicatorFilter.unavailableReason(offered: changed), reason)
            let dropped = switched(true, changed, from: switched(true, offered))
            XCTAssertTrue(dropped.isOn, reason)
            XCTAssertTrue(dropped.isDropped, reason)
            XCTAssertNil(dropped.filtering, reason)
            XCTAssertNil(dropped.predicate, reason)
            XCTAssertEqual(dropped.about(offered: changed), "\(reason), so events aren't filtered. Switch it off")
            XCTAssertEqual(switched(false, changed, from: dropped), IndicatorFilter(), reason)
            XCTAssertEqual(switched(true, offered, from: dropped), switched(true, offered), reason)
        }
    }

    /// One indicator that's on and marks the tables is enough, however many others don't.
    func testOneMarkingIndicatorIsEnough() throws {
        var mixed = offered.map { indicator -> Indicator in
            var indicator = indicator
            indicator.tableMarks = []
            return indicator
        }
        let first = try XCTUnwrap(offered.first { !$0.tableMarks.isEmpty })
        let index = try XCTUnwrap(mixed.firstIndex { $0.id == first.id })
        mixed[index].tableMarks = first.tableMarks
        XCTAssertNil(IndicatorFilter.unavailableReason(offered: mixed))
        let one = switched(true, mixed)
        XCTAssertFalse(one.isDropped)
        XCTAssertEqual(one.predicate, IndicatorSelection.indicator(first.id).predicate(offered: mixed, for: .search))
    }
}
