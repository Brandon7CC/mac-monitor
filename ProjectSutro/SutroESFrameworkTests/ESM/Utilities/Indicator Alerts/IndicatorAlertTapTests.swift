//
//  IndicatorAlertTapTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The tap on received events
/// Pins which live events reach notifications: none while nothing receives them, and only those the store kept, so
/// an event recorded before a Clear, while a trace is open, or read from a trace file never notifies.
final class IndicatorAlertTapTests: XCTestCase {
    /// Both switches on.
    private let both = IndicatorAlertSettings(high: true, medium: true)

    /// What a tap delivered.
    private let delivered = Recorded<[IndicatorAlertEvent]>()

    /// - Returns: A tap that records what it delivers.
    private func recordingTap() -> IndicatorAlertTap {
        let tap = IndicatorAlertTap()
        tap.configure(both, disabled: [], deliver: { [delivered] in delivered.append($0) })
        return tap
    }

    /// Insert live events, and wait until they're saved.
    ///
    /// - Parameters:
    ///   - messages: The events.
    ///   - store: The store.
    /// - Returns: Which of them it kept.
    private func insert(_ messages: [Message], into store: CoreDataController) -> Set<UUID> {
        let saved = expectation(description: "saved")
        var kept: Set<UUID> = []
        store.insertSystemEvents(messages: messages, watching: Set(messages.map(\.id))) {
            kept = $0
            saved.fulfill()
        }
        wait(for: [saved], timeout: 30)
        return kept
    }

    /// Clear, and wait until the Clear has finished.
    ///
    /// - Parameters:
    ///   - store: The store.
    ///   - source: Where the events come from next.
    private func clear(_ store: CoreDataController, source: CoreDataController.EventSource = .live) {
        let cleared = expectation(forNotification: CoreDataController.eventsDidClear, object: store)
        store.clearSystemEvents(source: source)
        wait(for: [cleared], timeout: 60)
    }

    /// With nothing to deliver to, or every switch off, no candidate is picked or held.
    func testNothingIsPickedWithoutADeliverer() throws {
        let message = try alertMessage([alertHit("XProtect", .high)])
        let tap = IndicatorAlertTap()
        XCTAssertEqual(tap.candidates(in: [message]), [])
        tap.configure(IndicatorAlertSettings(), disabled: [], deliver: { _ in XCTFail("Delivered") })
        XCTAssertEqual(tap.candidates(in: [message]), [])
        tap.hold([try alertEvent(UUID())])
        XCTAssertEqual(tap.takeHeld(), [])
        tap.configure(both, disabled: [], deliver: { _ in })
        XCTAssertEqual(tap.candidates(in: [message]).map(\.eventID), [message.id])
    }

    /// Held candidates are taken once, and only those whose events the store kept are delivered.
    func testOnlyKeptEventsAreDelivered() throws {
        let tap = recordingTap()
        let events = try (0..<3).map { _ in try alertEvent(UUID()) }
        tap.hold(events)
        XCTAssertEqual(tap.takeHeld(), events)
        XCTAssertEqual(tap.takeHeld(), [])
        tap.deliver(events, kept: [events[1].eventID, UUID()])
        tap.deliver(events, kept: [])
        XCTAssertEqual(delivered.all, [[events[1]]])
    }

    /// An event recorded before a Clear is inserted and dropped, so it isn't kept. One after it is.
    func testEventsFromBeforeAClearAreNotKept() throws {
        let store = CoreDataController(model: eventModel)
        let old = try alertMessage([alertHit("Dylib")], time: Date().addingTimeInterval(-5))
        clear(store)
        let new = try alertMessage([alertHit("Dylib")], time: Date().addingTimeInterval(1))
        XCTAssertEqual(insert([old, new], into: store), [new.id])
    }

    /// While a trace is open, no live event is kept.
    func testLiveEventsArentKeptWhileATraceIsOpen() throws {
        let store = CoreDataController(model: eventModel)
        clear(store, source: .trace(URL(fileURLWithPath: "/tmp/trace.jsonl")))
        let live = try alertMessage([alertHit("XProtect", .high)], time: Date().addingTimeInterval(1))
        XCTAssertEqual(insert([live], into: store), [])
    }

    /// Mac Monitor's own path: a live batch's eligible event notifies once it's saved, and its other events don't.
    /// A trace's events, inserted another way, never reach the tap.
    func testTheManagerNotifiesForSavedLiveEvents() throws {
        let manager = EndpointSecurityManager()
        let store = CoreDataController(model: eventModel)
        manager.coreDataContainer = store
        manager.indicatorAlertTap.configure(both, disabled: [], deliver: { [delivered] in delivered.append($0) })
        let alerting = try alertMessage([alertHit("XProtect", .high)])
        let quiet = try alertMessage([alertHit("Login", .low)])
        let replied = expectation(description: "replied")
        manager.receive(events: [try wire(alerting), try wire(quiet), try wire(alertMessage(nil))]) {
            replied.fulfill()
        }
        wait(for: [replied], timeout: 30)
        store.privateMOC.performAndWait {}
        XCTAssertEqual(delivered.all.flatMap { $0 }.map(\.eventID), [alerting.id])

        let trace = expectation(description: "trace saved")
        store.insertTraceEvents([try alertMessage([alertHit("XProtect", .high)])], clear: store.currentClear) {
            XCTAssertEqual($0, .saved)
            trace.fulfill()
        }
        wait(for: [trace], timeout: 30)
        XCTAssertEqual(delivered.all.count, 1)
        XCTAssertEqual(manager.indicatorAlertTap.takeHeld(), [])
    }
}
