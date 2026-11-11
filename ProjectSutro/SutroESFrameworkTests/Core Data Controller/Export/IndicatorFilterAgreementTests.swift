//
//  IndicatorFilterAgreementTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - The Filters sheet's indicator filter
/// Pins that an indicator filter, one indicator's or Any indicator under the Filters button, shows the events the
/// tables' dots mark (``EventIndicatorMatcher``): the Security Extension's stored verdicts decide an event that has
/// them, and only one without verdicts is matched now. The store narrows the events first, in SQLite as the tables'
/// search does, and never leaves out one that matches.
final class IndicatorFilterAgreementTests: XCTestCase {
    /// Never matches by its predicate: only a stored verdict names it.
    private static let stamped = Indicator(name: "Stamped", description: "", symbol: "star", color: .red,
                                           predicate: "event_type < 0", severity: .high)
    /// Matches every event by its predicate.
    private static let every = RecordIndicatorsPrecedenceTests.every

    /// An event stamped with one indicator's hit, one stamped with none, which the other would match now, and one
    /// with no verdicts, which it matches now. Each indicator filter keeps exactly the events whose dots it names.
    func testTheIndicatorFilterShowsTheEventsTheDotsMark() throws {
        let indicators = [Self.stamped, Self.every]
        let hit = IndicatorHit(Self.stamped, isDefault: false, evaluatedBy: .securityExtension)
        let container = try makeExportStore([event(IndicatorVerdicts([hit])), event(IndicatorVerdicts()), event(nil)])
        let selections: [(IndicatorSelection, [Int])] = [
            (.indicator(Self.stamped.id), [0]), (.indicator(Self.every.id), [2]), (.any, [0, 2]),
        ]
        let context = container.newBackgroundContext()
        try context.performAndWait {
            let stored = try context.fetch(ESMessage.request(sortedBy: [NSSortDescriptor(key: "insert_order",
                                                                                        ascending: true)]))
            XCTAssertEqual(stored.count, 3)
            let matcher = EventIndicatorMatcher(indicators)
            for (selection, expected) in selections {
                let predicate = try XCTUnwrap(selection.predicate(offered: indicators, for: .search))
                let dots = stored.indices.filter { index in
                    matcher.matches(stored[index]).contains { predicate.source.contains($0.id.uuidString) }
                }
                XCTAssertEqual(dots, expected, "\(selection) dots")
                let found = try search(predicate, in: context, indicators: indicators)
                    .compactMap { stored.firstIndex(of: $0) }
                XCTAssertEqual(found, expected, "\(selection) filter")
            }
        }
    }

    /// The store keeps an event stamped with a hit, never one stamped with none, and an event without verdicts only
    /// when a named indicator that's on could match it, as its own predicate narrows the store. One that's off, named
    /// directly since the Filters sheet doesn't offer it, matches no event without verdicts, though its predicate
    /// matches every event.
    func testTheStoreNarrowsByStoredVerdicts() throws {
        let hit = IndicatorHit(Self.stamped, isDefault: false, evaluatedBy: .securityExtension)
        let container = try makeExportStore([event(IndicatorVerdicts([hit])), event(IndicatorVerdicts()), event(nil)])
        var off = Self.every
        off.isEnabled = false
        let unnarrowed = ownIndicator("Unnarrowed", #"process.executable.path MATCHES ".*""#)
        let selected: (IndicatorSelection, [Indicator]) -> StreamFilter.Predicate? = {
            $0.predicate(offered: $1, for: .search)
        }
        let cases: [([Indicator], StreamFilter.Predicate?, [Int])] = [
            ([Self.stamped, Self.every], selected(.indicator(Self.stamped.id), [Self.stamped, Self.every]), [0]),
            ([Self.stamped, Self.every], selected(.indicator(Self.every.id), [Self.stamped, Self.every]), [0, 2]),
            ([Self.stamped, off], .listing([off.id], for: .search), [0]),
            ([Self.stamped, unnarrowed], selected(.indicator(unnarrowed.id), [Self.stamped, unnarrowed]), [0, 2]),
        ]
        let context = container.newBackgroundContext()
        try context.performAndWait {
            let order = [NSSortDescriptor(key: "insert_order", ascending: true)]
            let all = try context.fetch(ESMessage.request(sortedBy: order))
            for (indicators, predicate, expected) in cases {
                let narrow = try XCTUnwrap(try XCTUnwrap(predicate).storePredicate(listing: indicators))
                let request = ESMessage.request(sortedBy: order)
                request.predicate = narrow
                XCTAssertEqual(try context.fetch(request).compactMap { all.firstIndex(of: $0) }, expected,
                               "\(indicators.map(\.name)) \(predicate?.source ?? "")")
            }
        }
        let offered = IndicatorSelection.offered([Self.stamped, off])
        XCTAssertNil(IndicatorSelection.indicator(off.id).predicate(offered: offered, for: .search),
                     "Off isn't offered")
    }

    /// A predicate that doesn't name `indicators` narrows as it always has, and one that compares `indicators` with
    /// anything but constant identities isn't narrowed by them.
    func testOnlyIdentityComparisonsNarrowByVerdicts() throws {
        let indicators = [Self.stamped]
        let plain = try StreamFilter.Predicate("process.pid == 2", for: .search)
        XCTAssertEqual(plain.storePredicate(listing: indicators)?.predicateFormat,
                       plain.storePredicate?.predicateFormat)
        for source in [#"ANY indicators.name == "Stamped""#, #"ANY indicators.id == "not an identity""#,
                       #"ANY indicators.id BEGINSWITH "A""#] {
            XCTAssertNil(try StreamFilter.Predicate(source, for: .search).storePredicate(listing: indicators), source)
        }
        let one = try StreamFilter.Predicate(#"ANY indicators.id == "\#(Self.stamped.id.uuidString)""#, for: .search)
        XCTAssertNotNil(one.storePredicate(listing: indicators))
    }

    /// Search the store as the tables do: narrow by the store, then evaluate each candidate's record, listing the
    /// indicators for events without stored verdicts.
    ///
    /// - Parameters:
    ///   - predicate: The indicator filter.
    ///   - context: The store's context, on its queue.
    ///   - indicators: The Mac's indicators.
    /// - Returns: The events it keeps, in order.
    /// - Throws: The fetch's error, or the predicate's.
    private func search(_ predicate: StreamFilter.Predicate, in context: NSManagedObjectContext,
                        indicators: [Indicator]) throws -> [ESMessage] {
        let request = ESMessage.request(sortedBy: [NSSortDescriptor(key: "insert_order", ascending: true)])
        request.predicate = predicate.storePredicate(listing: indicators)
        return try predicate.searching(indicators: indicators) {
            try context.fetch(request).filter { try predicate.evaluate(on: $0) }
        }
    }

    /// - Parameter verdicts: The verdicts to stamp, or `nil` for none.
    /// - Returns: The synthetic corpus's first event, stamped.
    private func event(_ verdicts: IndicatorVerdicts?) -> Message {
        var message = (try? SyntheticCorpus.records().first?.message)!
        message.indicators = verdicts
        return message
    }
}
