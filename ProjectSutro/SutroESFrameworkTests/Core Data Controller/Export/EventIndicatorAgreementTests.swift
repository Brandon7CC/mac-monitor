//
//  EventIndicatorAgreementTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - One answer for an event
/// Pins that every surface gives an event the same indicators: the event tables' dots, Correlation, Groups and the
/// Indicators popover (``EventIndicatorMatcher``), a search that names `indicators`, and the record the JSON tab
/// shows and an export writes. Each reads the Security Extension's stored verdicts when the event has them, and
/// matches the indicators now only when it has none.
final class EventIndicatorAgreementTests: XCTestCase {
    /// Never matches by its predicate: only a stored verdict names it.
    private static let stamped = Indicator(name: "Stamped", description: "", symbol: "star", color: .red,
                                           predicate: "event_type < 0", severity: .high)
    /// Matches every event by its predicate.
    private static let every = RecordIndicatorsPrecedenceTests.every
    /// An indicator the list no longer has, such as one deleted since the event was stamped.
    private static let deleted = Indicator(name: "Deleted since", description: "", symbol: "star", color: .red,
                                           predicate: "TRUEPREDICATE", severity: .low)

    /// An event stamped with two verdicts, one of an indicator since deleted, one stamped with none, which the
    /// list's indicators would match, and one with no verdicts, which they match now. Each surface lists the same
    /// indicators for each.
    func testDotsSearchAndExportAgree() throws {
        let indicators = [Self.stamped, Self.every]
        let hits = [IndicatorHit(Self.stamped, isDefault: false, evaluatedBy: .securityExtension),
                    IndicatorHit(Self.deleted, isDefault: false, evaluatedBy: .securityExtension)]
        let events = [event(IndicatorVerdicts(hits)), event(IndicatorVerdicts()), event(nil)]
        let expected = [[Self.stamped.id, Self.deleted.id], [], [Self.every.id]]
        try withEventStore(events) { _, stored in
            let matcher = EventIndicatorMatcher(indicators)
            for (event, expected) in zip(stored, expected) {
                let dots = matcher.matches(event)
                XCTAssertEqual(dots.map(\.id), expected, "Dots")
                XCTAssertEqual(try recorded(event, with: indicators), expected, "Export")
                for id in [Self.stamped.id, Self.every.id, Self.deleted.id] {
                    let search = try StreamFilter.Predicate(#"ANY indicators.id == "\#(id.uuidString)""#)
                    let found = try search.searching(indicators: indicators) { try search.evaluate(on: event) }
                    XCTAssertEqual(found, expected.contains(id), "Search for \(id)")
                }
            }
            let gone = try XCTUnwrap(matcher.matches(stored[0]).last)
            XCTAssertEqual(gone.name, Self.deleted.name)
            XCTAssertEqual(gone.severity, .low)
        }
    }

    /// A verdict's indicator shows as the list has it now, though it's been turned off since, and before one the
    /// list no longer has. Summaries list every indicator in the list's order.
    func testVerdictsShowAsTheListHasThem() throws {
        var off = Self.every
        off.isEnabled = false
        off.tableMarks = [.dot, .symbol]
        let hits = [IndicatorHit(Self.deleted, isDefault: false, evaluatedBy: .securityExtension),
                    IndicatorHit(off, isDefault: false, evaluatedBy: .securityExtension)]
        try withEventStore([event(IndicatorVerdicts(hits)), event(nil)]) { _, stored in
            let matcher = EventIndicatorMatcher([Self.stamped, off])
            XCTAssertEqual(matcher.matches(stored[0]), [off, Indicator(verdict: hits[0])])
            XCTAssertEqual(matcher.matches(stored[1]), [], "Off, so not matched now")
            XCTAssertEqual(matcher.order, [Self.stamped, off])
        }
    }

    /// - Parameter verdicts: The verdicts to stamp, or `nil` for none.
    /// - Returns: The synthetic corpus's first event, stamped.
    private func event(_ verdicts: IndicatorVerdicts?) -> Message {
        var message = (try? SyntheticCorpus.records().first?.message)!
        message.indicators = verdicts
        return message
    }

    /// - Parameters:
    ///   - event: A stored event, on its context's queue.
    ///   - indicators: The indicators the record's writer lists.
    /// - Returns: The identities its record lists under `indicators`, in order.
    /// - Throws: When the record isn't a JSON object.
    private func recorded(_ event: ESMessage, with indicators: [Indicator]) throws -> [UUID] {
        let json = RecordIndicators.encoding(with: RecordIndicators(indicators)) {
            ProcessHelpers.eventToJSON(value: event)
        }
        let record = try jsonObject(Data(json.utf8))
        return try XCTUnwrap(record["indicators"] as? [[String: Any]]).compactMap {
            ($0["id"] as? String).flatMap(UUID.init(uuidString:))
        }
    }
}
