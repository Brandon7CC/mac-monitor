//
//  SensorServiceNetworkTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Settings recording network flows
/// Pins Settings > General's two network switches over real NSXPC connections: Record network flows subscribes the
/// two flow events by name, Record URL paths travels as ``NetworkFlowEvent/urlPathsSubscriptionName``, both are on
/// until turned off, both outlive a capture session as subscriptions do, and a Mac whose network statistics can't be
/// read refuses the flows, as the Security Extension does to a Mac Monitor that doesn't own the event stream.
final class SensorServiceNetworkTests: XCTestCase {
    private let flows = FlowClientHarness()
    private let agent = RecordingAgent()

    /// A service on fake clients reading flows from a client, with saved sets in fresh directories.
    ///
    /// - Parameter flows: The client: the test's unless given.
    /// - Returns: The harness.
    /// - Throws: If a saved set can't be made.
    private func makeHarness(flows: FlowClientHarness? = nil) throws -> SensorServiceHarness {
        let suite = "SensorServiceNetworkTests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        return SensorServiceHarness(savedMutes: SavedMuteSet(testing: try makeMuteStore()),
                                    savedIndicators: try makeSavedIndicatorSet(),
                                    commandLineAccess: CommandLineAccessStore(defaults: defaults),
                                    switches: EnrichmentSwitchStore(defaults: defaults),
                                    flows: (flows ?? self.flows).client)
    }

    /// What a connection reads as subscribed.
    ///
    /// - Parameter connection: The connection.
    /// - Returns: The names, or `nil` without an answer.
    private func subscriptions(_ connection: NSXPCConnection) -> [String]? {
        connection.sensor { $0.eventSubscriptions(reply: $1) }
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

    /// Record network flows is on until turned off: the two events are subscribed by name from the start, which opens
    /// the client's socket, and their flows reach Mac Monitor. Turning it off closes the socket, and on opens it.
    func testRecordNetworkFlows() throws {
        let harness = try makeHarness()
        let connection = harness.connect(agent: agent)
        defer { connection.invalidate() }
        XCTAssertEqual(connection.handshake(), .success)
        let names = try XCTUnwrap(subscriptions(connection))
        XCTAssertTrue(names.contains("new_flow") && names.contains("flow_closed"), "On by default")
        XCTAssertNotNil(flows.socket)
        XCTAssertTrue(flows.play())
        XCTAssertTrue(waitUntil { self.agent.flows.count == 2 })
        XCTAssertEqual(agent.flows.map(\.es_event_type), ["new_flow", "flow_closed"])
        XCTAssertEqual(set(connection, "new_flow", false), true)
        XCTAssertEqual(set(connection, "flow_closed", false), true)
        XCTAssertNil(flows.socket)
        XCTAssertEqual(set(connection, "new_flow", true), true)
        XCTAssertNotNil(flows.socket)
    }

    /// Record URL paths is on until turned off. Off, a flow's URL ends at its host. It outlives a capture session,
    /// as subscriptions do. ``SensorServiceRestartTests`` pins what a restart keeps.
    func testRecordURLPaths() throws {
        let harness = try makeHarness()
        let connection = harness.connect(agent: agent)
        XCTAssertEqual(connection.handshake(), .success)
        XCTAssertEqual(subscriptions(connection)?.contains(NetworkFlowEvent.urlPathsSubscriptionName), true)
        XCTAssertEqual(set(connection, NetworkFlowEvent.urlPathsSubscriptionName, false), true)
        XCTAssertEqual(subscriptions(connection)?.contains(NetworkFlowEvent.urlPathsSubscriptionName), false)
        XCTAssertEqual(set(connection, "flow_closed", false), true, "One record per flow played")
        XCTAssertTrue(flows.play())
        XCTAssertTrue(waitUntil { self.agent.flows.count == 1 })
        XCTAssertEqual(agent.flows.first?.event.networkFlow?.url, FlowClientHarness.host)
        connection.invalidate()
        XCTAssertTrue(waitUntil { harness.owner == nil })
        XCTAssertNil(flows.socket, "Capture stopped with its owner")
        let again = harness.connect(agent: agent)
        defer { again.invalidate() }
        XCTAssertEqual(again.handshake(), .success)
        let names = try XCTUnwrap(subscriptions(again))
        XCTAssertFalse(names.contains(NetworkFlowEvent.urlPathsSubscriptionName))
        XCTAssertTrue(names.contains("new_flow"), "The flows outlive the session too")
        XCTAssertNotNil(flows.socket)
    }

    /// A flow event is refused when the client can't open its socket, and isn't reported as subscribed, by default
    /// or when asked for. The rest of capture starts as usual.
    func testAnUnreadableMacRefusesTheFlows() throws {
        let harness = try makeHarness(flows: FlowClientHarness(refusing: true))
        let connection = harness.connect()
        defer { connection.invalidate() }
        XCTAssertEqual(connection.handshake(), .success)
        let names = try XCTUnwrap(subscriptions(connection))
        XCTAssertFalse(names.contains("new_flow") || names.contains("flow_closed"))
        XCTAssertTrue(names.contains("ES_EVENT_TYPE_NOTIFY_EXEC"))
        XCTAssertEqual(set(connection, "new_flow", true), false)
        XCTAssertEqual(subscriptions(connection)?.contains("new_flow"), false)
    }

    /// A Mac that reads flows refuses a flow event to a Mac Monitor before any owns the event stream, and to one
    /// whose handshake says another owns it. Settings words each refusal by the handshake
    /// (``NewClientResult/refusal(answered:onThisMac:)``).
    func testRefusalsWithoutTheStream() throws {
        let harness = try makeHarness()
        let (owner, second) = (harness.connect(), harness.connect())
        defer { [owner, second].forEach { $0.invalidate() } }
        XCTAssertEqual(set(owner, "new_flow", false), false, "Before capture runs")
        XCTAssertEqual(owner.handshake(), .success)
        XCTAssertEqual(second.handshake(), .streamOwned)
        XCTAssertEqual(set(second, "new_flow", false), false)
        XCTAssertEqual(set(owner, "new_flow", false), true)
    }

    /// Turning the flows off and on again at once leaves them recording: the client's socket is open after.
    func testOffThenOnAtOnceKeepsRecording() throws {
        let harness = try makeHarness()
        let connection = harness.connect(agent: agent)
        defer { connection.invalidate() }
        XCTAssertEqual(connection.handshake(), .success)
        XCTAssertEqual(set(connection, "flow_closed", false), true, "One record per flow played")
        let replies = Recorded<Bool>()
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in } as? SensorProtocol
        proxy?.setSubscription("new_flow", enabled: false, reply: replies.append)
        proxy?.setSubscription("new_flow", enabled: true, reply: replies.append)
        XCTAssertTrue(waitUntil { replies.all.count == 2 })
        XCTAssertEqual(replies.all, [true, true])
        XCTAssertNotNil(flows.socket)
        XCTAssertTrue(flows.play())
        XCTAssertTrue(waitUntil { self.agent.flows.count == 1 })
    }
}
