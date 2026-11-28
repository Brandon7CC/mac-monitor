//
//  MacMonitorEventTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Mac Monitor's own events
/// Pins the names and numbers of Mac Monitor's own events, how every event is named for people and the app, and the
/// symbols the network events draw.
final class MacMonitorEventTests: XCTestCase {
    /// The two events have their numbers, far past Endpoint Security's, and one name each, which reads back.
    func testNamesAndNumbers() {
        XCTAssertEqual(MacMonitorEvent.allCases.map(\.rawValue), [1_001, 1_002])
        XCTAssertEqual(MacMonitorEvent.allCases.map(\.name), ["new_flow", "flow_closed"])
        XCTAssertEqual(MacMonitorEvent.typeLimit, 1_003)
        XCTAssertGreaterThan(1_001, Int(ES_EVENT_TYPE_LAST.rawValue))
        for event in MacMonitorEvent.allCases {
            XCTAssertEqual(eventTypeToString(from: event.type), event.name)
            XCTAssertEqual(eventStringToType(from: event.name), event.type)
            XCTAssertEqual(MacMonitorEvent(event.type), event)
            XCTAssertEqual(MacMonitorEvent(name: event.name), event)
            XCTAssertFalse(supportedEvents.contains(event.type), "No Endpoint Security client subscribes to it")
        }
        for raw: UInt32 in [1_000, 1_003, ES_EVENT_TYPE_NOTIFY_EXEC.rawValue] {
            XCTAssertNil(MacMonitorEvent(es_event_type_t(rawValue: raw)), "\(raw)")
        }
        XCTAssertEqual(eventTypeToString(from: es_event_type_t(rawValue: 1_000)), "ES_EVENT_TYPE_LAST")
        for name in ["NEW_FLOW", "ES_EVENT_TYPE_NOTIFY_NEW_FLOW", "new_flow "] {
            XCTAssertEqual(eventStringToType(from: name), ES_EVENT_TYPE_LAST, name)
            XCTAssertNil(MacMonitorEvent(name: name), name)
        }
    }

    /// Short and full names: an Endpoint Security event's with and without its prefix, a Mac Monitor event's alike,
    /// in any case.
    func testShortAndFullNames() {
        XCTAssertEqual(EventNames.shortName("ES_EVENT_TYPE_NOTIFY_EXEC"), "exec")
        XCTAssertEqual(EventNames.shortName("new_flow"), "new_flow")
        XCTAssertEqual(EventNames.fullName("exec"), "ES_EVENT_TYPE_NOTIFY_EXEC")
        XCTAssertEqual(EventNames.fullName("ES_EVENT_TYPE_NOTIFY_EXEC"), "ES_EVENT_TYPE_NOTIFY_EXEC")
        XCTAssertEqual(EventNames.fullName("NEW_FLOW"), "new_flow")
        XCTAssertEqual(EventNames.fullName("flow_closed"), "flow_closed")
        XCTAssertEqual(CommandLineEvents.notifyEvent(named: "new_flow"), MacMonitorEvent.new_flow.type)
        XCTAssertEqual(CommandLineEvents.notifyEvent(named: "Flow_Closed"), MacMonitorEvent.flow_closed.type)
        XCTAssertEqual(CommandLineEvents.notifyEvent(named: "exec"), ES_EVENT_TYPE_NOTIFY_EXEC)
        XCTAssertNil(CommandLineEvents.notifyEvent(named: "flow"))
    }

    /// The app labels network events `NETWORK_NEW_FLOW`, so they sort beside the NOTIFY events, and the chart
    /// `NEW_FLOW`, as it labels `EXEC`. Endpoint Security's labels are unchanged.
    func testLabels() {
        XCTAssertEqual(EventNames.label("new_flow"), "NETWORK_NEW_FLOW")
        XCTAssertEqual(EventNames.label("flow_closed"), "NETWORK_FLOW_CLOSED")
        XCTAssertEqual(EventNames.label("ES_EVENT_TYPE_NOTIFY_EXEC"), "ES_EVENT_TYPE_NOTIFY_EXEC")
        XCTAssertEqual(EventNames.chartLabel("new_flow"), "NEW_FLOW")
        XCTAssertEqual(EventNames.chartLabel("flow_closed"), "FLOW_CLOSED")
        XCTAssertEqual(EventNames.chartLabel("ES_EVENT_TYPE_NOTIFY_EXEC"), "EXEC")
        let labels = ["ES_EVENT_TYPE_NOTIFY_OPEN", "new_flow", "ES_EVENT_TYPE_NOTIFY_EXEC"].map(EventNames.label)
            .sorted()
        XCTAssertEqual(labels, ["ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_NOTIFY_OPEN", "NETWORK_NEW_FLOW"])
    }

    /// The network events draw `network` and `xmark.circle`, on macOS 13 too, rather than an unknown event's mark.
    func testSymbols() {
        let ventura = OperatingSystemVersion(majorVersion: 13, minorVersion: 1, patchVersion: 0)
        for os in [ventura, ProcessInfo.processInfo.operatingSystemVersion] {
            let symbols = ModeledEvent.symbols(on: os)
            XCTAssertEqual(symbols["new_flow"], "network")
            XCTAssertEqual(symbols["flow_closed"], "xmark.circle")
        }
        XCTAssertEqual(eventStringToImage(from: "new_flow"), "network")
    }
}
