//
//  EventChartLabelsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The mini-chart's bars
/// Pins that every event Mac Monitor can record has a bar on the mini-chart, each under its own label.
final class EventChartLabelsTests: XCTestCase {
    /// Every Endpoint Security event Mac Monitor can subscribe to, on any macOS it runs on, and each of its own events
    /// has a bar, and every bar is one of theirs. No two events share a bar, and none is listed twice.
    func testEveryRecordableEventHasABar() {
        let names = ModeledEvent.all.map { eventTypeToString(from: $0.type) } + MacMonitorEvent.allCases.map(\.name)
        let labels = names.map(EventChartLabels.label(for:))
        for (name, label) in zip(names, labels) where !EventChartLabels.order.contains(label) {
            XCTFail("\(name) has no bar")
        }
        for bar in EventChartLabels.order where !labels.contains(bar) { XCTFail("\(bar) is no event's bar") }
        XCTAssertEqual(Set(labels).count, names.count, "Two events share a bar")
        XCTAssertEqual(Set(EventChartLabels.order).count, EventChartLabels.order.count, "A bar is listed twice")
    }

    /// The network events' bars come after the last Endpoint Security event's, so no bar before them moves or takes
    /// another color. A long name keeps its shorter label.
    func testTheFlowsBarsComeLast() {
        XCTAssertEqual(EventChartLabels.order.suffix(3), ["UIPC_BIND", "NEW_FLOW", "FLOW_CLOSED"])
        XCTAssertEqual(EventChartLabels.label(for: "flow_closed"), "FLOW_CLOSED")
        XCTAssertEqual(EventChartLabels.label(for: "ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK"), "LW_UNLOCK")
        XCTAssertEqual(EventChartLabels.label(for: "ES_EVENT_TYPE_NOTIFY_EXEC"), "EXEC")
    }
}
