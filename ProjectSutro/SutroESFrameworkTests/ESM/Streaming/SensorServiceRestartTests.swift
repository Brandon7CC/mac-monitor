//
//  SensorServiceRestartTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/26/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - What a restart keeps
/// Pins what Settings > General's enrichment switches keep when the Security Extension restarts, over real NSXPC
/// connections. Record network flows, Scan written files and Record URL paths are on until the owner turns one off. A
/// restart, a new service on the same store, keeps each change, and its capture scans and keeps URL paths as they
/// say. Endpoint Security events go back to their defaults, and a Mac whose network statistics can't be read leaves
/// the flows on for the next start.
final class SensorServiceRestartTests: XCTestCase {
    /// The switches by their subscription names, sorted: the flows' two events, URL paths and scanning.
    private let switches = ["flow_closed", "new_flow", NetworkFlowEvent.urlPathsSubscriptionName,
                            YaraScan.subscriptionName]

    /// Start a service on fake clients and connect to it as the owner of its event stream. Both last until the test
    /// ends.
    ///
    /// - Parameters:
    ///   - store: Where the service keeps its switches.
    ///   - flows: The client the service reads flows from.
    ///   - agent: Mac Monitor's side, which receives the events.
    /// - Returns: The owner's connection, and the service's harness.
    /// - Throws: If a saved set can't be made.
    private func owner(of store: EnrichmentSwitchStore, flows: FlowClientHarness = FlowClientHarness(),
                       agent: RecordingAgent = RecordingAgent()) throws
        -> (connection: NSXPCConnection, harness: SensorServiceHarness) {
        let harness = SensorServiceHarness(savedMutes: SavedMuteSet(testing: try makeMuteStore()),
                                           savedIndicators: try makeSavedIndicatorSet(),
                                           commandLineAccess: CommandLineAccessStore(defaults: makeDefaults()),
                                           switches: store, flows: flows.client)
        let connection = harness.connect(agent: agent)
        addTeardownBlock { withExtendedLifetime(harness) { connection.invalidate() } }
        XCTAssertEqual(connection.handshake(), .success)
        return (connection, harness)
    }

    /// What a connection reads as subscribed.
    ///
    /// - Parameter connection: The connection.
    /// - Returns: The names, or `nil` without an answer.
    private func subscriptions(_ connection: NSXPCConnection) -> [String]? {
        connection.sensor { $0.eventSubscriptions(reply: $1) }
    }

    /// The switches a connection reads as on.
    ///
    /// - Parameter connection: The connection.
    /// - Returns: Their names, sorted, or `nil` without an answer.
    private func switchesOn(_ connection: NSXPCConnection) -> [String]? {
        subscriptions(connection)?.filter(switches.contains)
    }

    /// Turn a subscription on or off from a connection.
    ///
    /// - Parameters:
    ///   - connection: The connection.
    ///   - name: The subscription.
    ///   - enabled: On or off.
    /// - Returns: The reply.
    private func set(_ connection: NSXPCConnection, _ name: String, _ enabled: Bool) -> Bool? {
        connection.sensor { $0.setSubscription(name, enabled: enabled, reply: $1) }
    }

    /// A fresh store has every switch on.
    func testEverySwitchStartsOn() throws {
        XCTAssertEqual(switchesOn(try owner(of: EnrichmentSwitchStore(defaults: makeDefaults())).connection), switches)
    }

    /// Each switch turned off stays off when the Security Extension restarts, and is on again after a restart once
    /// it's turned back on. The restarted capture scans written files, and keeps URL paths, only as the switches say.
    /// An Endpoint Security event turned off is subscribed again after a restart.
    func testARestartKeepsEachSwitch() throws {
        let store = EnrichmentSwitchStore(defaults: makeDefaults())
        let first = try owner(of: store).connection
        for name in switches + ["ES_EVENT_TYPE_NOTIFY_EXEC"] { XCTAssertEqual(set(first, name, false), true, name) }
        let restarted = try owner(of: store)
        XCTAssertEqual(switchesOn(restarted.connection), [])
        XCTAssertEqual(restarted.harness.scansWrittenFiles, false, "Its capture doesn't scan")
        XCTAssertEqual(subscriptions(restarted.connection)?.contains("ES_EVENT_TYPE_NOTIFY_EXEC"), true)
        XCTAssertEqual(set(restarted.connection, "new_flow", true), true)
        XCTAssertEqual(set(restarted.connection, YaraScan.subscriptionName, true), true)
        let (flows, agent) = (FlowClientHarness(), RecordingAgent())
        let again = try owner(of: store, flows: flows, agent: agent)
        XCTAssertEqual(switchesOn(again.connection), ["new_flow", YaraScan.subscriptionName])
        XCTAssertEqual(again.harness.scansWrittenFiles, true, "Its capture scans")
        XCTAssertTrue(flows.play())
        XCTAssertTrue(waitUntil { agent.flows.count == 1 })
        XCTAssertEqual(agent.flows.first?.event.networkFlow?.url, "https://en.wikipedia.org", "URL paths stay off")
        for name in switches { XCTAssertEqual(set(restarted.connection, name, true), true, name) }
        XCTAssertEqual(switchesOn(try owner(of: store).connection), switches)
    }

    /// A Mac whose network statistics can't be read starts without the flows and refuses them, and a change to
    /// another event leaves capture without them. None of that is the owner turning them off, so the next start on a
    /// Mac that can read them records them.
    func testAnUnreadableMacLeavesTheFlowsOn() throws {
        let store = EnrichmentSwitchStore(defaults: makeDefaults())
        let unreadable = try owner(of: store, flows: FlowClientHarness(refusing: true)).connection
        XCTAssertEqual(switchesOn(unreadable), [NetworkFlowEvent.urlPathsSubscriptionName, YaraScan.subscriptionName])
        XCTAssertEqual(set(unreadable, "new_flow", true), false)
        XCTAssertEqual(set(unreadable, "ES_EVENT_TYPE_NOTIFY_EXEC", false), true)
        XCTAssertEqual(switchesOn(try owner(of: store).connection), switches)
    }
}
