//
//  FieldFilterTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Field filters
/// Pins what each ``FieldFilter`` is on the wire and which event it checks, and the table a capture lane looks it up
/// in.
final class FieldFilterTests: XCTestCase {
    /// Every filter is on an event Mac Monitor streams, named after it, and never read as an event, so a Security
    /// Extension older than 3.0.1 refuses it.
    func testEveryFilterIsNamedAfterAnEventItNeverNames() {
        for filter in FieldFilter.allCases {
            XCTAssertTrue(supportedEvents.contains(filter.event), filter.rawValue)
            XCTAssertTrue(filter.rawValue.hasPrefix(eventTypeToString(from: filter.event) + "."), filter.rawValue)
            XCTAssertEqual(eventStringToType(from: filter.rawValue), ES_EVENT_TYPE_LAST, filter.rawValue)
            XCTAssertFalse(filter.title.isEmpty)
            XCTAssertFalse(filter.help.contains("\u{2026}"), "Three periods, not the ellipsis character")
        }
        XCTAssertEqual(FieldFilter.modifiedCloses.rawValue, "ES_EVENT_TYPE_NOTIFY_CLOSE.modified")
    }

    /// Close offers the modified-only filter. Exec offers none.
    func testWhichEventsOfferFilters() {
        XCTAssertEqual(FieldFilter.offered(for: ES_EVENT_TYPE_NOTIFY_CLOSE), [.modifiedCloses])
        XCTAssertEqual(FieldFilter.offered(for: ES_EVENT_TYPE_NOTIFY_EXEC), [])
        XCTAssertEqual(FieldFilter.filteredEvents, [ES_EVENT_TYPE_NOTIFY_CLOSE])
    }

    /// The table has one entry per raw value up to the largest filtered event, and only that entry is set. No
    /// filters is an empty table, which a lane never indexes.
    func testTheTableHoldsEachFilterAtItsEvent() {
        let close = Int(ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue)
        let table = FieldFilter.table([.modifiedCloses])
        XCTAssertEqual(table.count, close + 1)
        XCTAssertEqual(table[close], .modifiedCloses)
        XCTAssertEqual(table.compactMap { $0 }.count, 1)
        XCTAssertTrue(FieldFilter.table([]).isEmpty)
    }

    /// A close passes only if the file was modified: one changed only through a writable mapping doesn't.
    func testOnlyModifiedClosesPass() {
        XCTAssertTrue(FieldFilter.modifiedCloses.admits(closeMessage(modified: true, global: 1).raw))
        XCTAssertFalse(FieldFilter.modifiedCloses.admits(closeMessage(modified: false, global: 2).raw))
        XCTAssertFalse(FieldFilter.modifiedCloses.admits(closeMessage(modified: false, wasMappedWritable: true,
                                                                      global: 3).raw))
    }
}
