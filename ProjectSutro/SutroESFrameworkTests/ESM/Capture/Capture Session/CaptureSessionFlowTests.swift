//
//  CaptureSessionFlowTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Network flows in a capture session
/// Pins how a capture session records network flows on its network lane: the client's socket is open while a session
/// subscribes to a flow event and is shared by every session, a client that can't open refuses the subscription,
/// recording and draining include the lane, and nothing of it reads as Endpoint Security's.
final class CaptureSessionFlowTests: XCTestCase {
    private let factory = FakeEndpointSecurityClientFactory()
    private let emitted = EmittedEvents()
    private let flows = FlowClientHarness()

    /// A session that can record flows, recording.
    ///
    /// - Parameters:
    ///   - events: What it subscribes to from the start.
    ///   - factory: Makes its Endpoint Security clients: the test's unless given.
    ///   - flows: The client it reads flows from: the test's unless given.
    ///   - emitted: Collects what it emits: the test's unless given.
    /// - Returns: The session.
    /// - Throws: ``CaptureStartError`` if it couldn't start.
    private func makeFlowSession(_ events: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_EXIT],
                                 factory: FakeEndpointSecurityClientFactory? = nil, flows: FlowClientHarness? = nil,
                                 emitted: EmittedEvents? = nil) throws -> CaptureSession {
        let session = try makeSession(CaptureConfiguration(events: events, label: "Test"),
                                      factory: factory ?? self.factory, flows: (flows ?? self.flows).client,
                                      emitted: emitted ?? self.emitted)
        session.isRecording = true
        return session
    }

    /// The flow events a session's events name, as their names.
    ///
    /// - Parameter session: The session.
    /// - Returns: The names of its subscribed flow events.
    private func flowEvents(of session: CaptureSession) -> [String] {
        session.subscribedEvents.compactMap { MacMonitorEvent($0)?.name }
    }

    /// Subscribing to a flow event opens the client's socket, and its flows are emitted on the network lane. Only
    /// a session given a client keeps flow events.
    func testSubscribingOpensTheClient() throws {
        let session = try makeFlowSession()
        let calls = factory.clients.map(\.calls.count)
        XCTAssertTrue(flows.sockets.all.isEmpty, "No socket until a flow event is subscribed")
        XCTAssertTrue(session.setSubscription(MacMonitorEvent.new_flow.type, enabled: true))
        XCTAssertTrue(session.setSubscription(.flow_closed, enabled: true))
        XCTAssertEqual(flows.sockets.all.count, 1)
        XCTAssertEqual(flowEvents(of: session), ["new_flow", "flow_closed"])
        XCTAssertTrue(flows.play())
        XCTAssertEqual(emitted.all.map(\.eventClass), [.network, .network])
        XCTAssertEqual(factory.clients.map(\.calls.count), calls, "Endpoint Security is never asked")
        let without = try makeSession(CaptureConfiguration(events: [MacMonitorEvent.new_flow.type], label: "Test"),
                                      factory: FakeEndpointSecurityClientFactory())
        XCTAssertEqual(without.subscribedEvents, [])
        XCTAssertFalse(without.setSubscription(.new_flow, enabled: true))
    }

    /// A session that starts with flow events opens the socket, and one whose client can't open starts without them
    /// and says why. Turning flows on then is refused too, with nothing subscribed.
    func testAnUnavailableClientRefusesTheSubscription() throws {
        let started = try makeFlowSession([ES_EVENT_TYPE_NOTIFY_EXIT, MacMonitorEvent.new_flow.type])
        XCTAssertEqual(flowEvents(of: started), ["new_flow"])
        XCTAssertNotNil(flows.socket)
        let refusing = FlowClientHarness(refusing: true)
        let session = try makeFlowSession([ES_EVENT_TYPE_NOTIFY_EXIT, MacMonitorEvent.new_flow.type],
                                          factory: FakeEndpointSecurityClientFactory(), flows: refusing)
        XCTAssertEqual(session.subscribedEvents, [ES_EVENT_TYPE_NOTIFY_EXIT])
        XCTAssertEqual(session.flowProblem, "Operation not permitted (errno 1)")
        XCTAssertFalse(session.setSubscription(.flow_closed, enabled: true))
        XCTAssertEqual(session.subscribedEvents, [ES_EVENT_TYPE_NOTIFY_EXIT])
        XCTAssertNil(session.flowStatistics(), "It never recorded flows")
    }

    /// Unsubscribing from the last flow event closes the socket. Two sessions share one socket, which stays open
    /// until the last of them stops, and each gets every flow.
    func testSessionsShareOneSocket() throws {
        let other = EmittedEvents()
        let first = try makeFlowSession([MacMonitorEvent.new_flow.type])
        let second = try makeFlowSession([MacMonitorEvent.new_flow.type],
                                         factory: FakeEndpointSecurityClientFactory(), emitted: other)
        XCTAssertEqual(flows.sockets.all.count, 1)
        XCTAssertTrue(flows.play())
        XCTAssertEqual(emitted.all.count, 1)
        XCTAssertEqual(other.all.count, 1)
        XCTAssertTrue(first.setSubscription(.new_flow, enabled: false))
        XCTAssertNotNil(flows.socket, "The second session still records flows")
        second.stop()
        XCTAssertNil(flows.socket)
        XCTAssertEqual(flows.sockets.all.count, 1)
        XCTAssertTrue(first.setSubscription(.new_flow, enabled: true))
        XCTAssertEqual(flows.sockets.all.count, 2, "Subscribing again opens a new socket")
    }

    /// Flows handed over while the session isn't recording are skipped and counted with the Endpoint Security
    /// clients' skipped messages, so a paused stream counts them.
    func testRecordingOffSkipsFlows() throws {
        let session = try makeFlowSession([MacMonitorEvent.new_flow.type, MacMonitorEvent.flow_closed.type])
        session.isRecording = false
        XCTAssertTrue(flows.play(2))
        XCTAssertTrue(emitted.all.isEmpty)
        XCTAssertEqual(session.skippedMessages, 4)
        XCTAssertEqual(session.flowStatistics()?.skipped, 4)
    }

    /// A drain delivers every flow the client has read, after the Endpoint Security clients have synced, and the
    /// lane takes no more. Stopping unregisters the lane, which closes the socket.
    func testDrainAndStop() throws {
        let session = try makeFlowSession([MacMonitorEvent.new_flow.type])
        flows.socket?.deliver(flows.flow(), waking: false)
        let drained = expectation(description: "Drained")
        session.drain(on: .main) { drained.fulfill() }
        wait(for: [drained], timeout: 5)
        XCTAssertEqual(emitted.all.count, 1, "What the socket held before the drain")
        XCTAssertTrue(flows.play())
        XCTAssertEqual(emitted.all.count, 1, "Nothing after it")
        session.stop()
        XCTAssertNil(flows.socket)
        XCTAssertEqual(session.flowStatistics()?.records, 4, "Each flow's opening and close, counted when ignored")
    }

    /// The Endpoint Security statistics, drop reports and lanes never include the network lane, whose losses are
    /// its own.
    func testEndpointSecurityStatisticsLeaveTheLaneOut() throws {
        let session = try makeFlowSession([ES_EVENT_TYPE_NOTIFY_EXIT, MacMonitorEvent.new_flow.type])
        XCTAssertTrue(flows.feed(flows.flow(lost: 3)))
        XCTAssertEqual(session.statistics().map(\.eventClass), EventClass.endpointSecurity)
        XCTAssertEqual(session.statistics().map(\.subscribedEvents), [1, 0, 0])
        XCTAssertEqual(session.statistics().reduce(0) { $0 + $1.dropped }, 0)
        XCTAssertTrue(session.takeDropReport().isEmpty)
        let statistics = try XCTUnwrap(session.flowStatistics())
        XCTAssertEqual(statistics.socketsLost, 3)
        XCTAssertEqual(statistics.records, 2)
    }

    /// The configuration's URL paths, mutes and indicators reach the network lane, and later changes reach it too.
    func testTheLaneFollowsTheSession() throws {
        var configuration = CaptureConfiguration(events: [MacMonitorEvent.new_flow.type], label: "Test")
        configuration.recordsURLPaths = false
        configuration.mutes = MuteList([PathMute(path: "/usr/bin/nscurl", type: ES_MUTE_PATH_TYPE_LITERAL)])
        let session = try makeSession(configuration, factory: factory, flows: flows.client, emitted: emitted)
        session.isRecording = true
        /// Each flow's close isn't subscribed, so each flow makes one event.
        XCTAssertTrue(flows.play())
        XCTAssertTrue(session.applyMutes(MuteList([PathMute(path: "/usr/bin/curl", type: ES_MUTE_PATH_TYPE_LITERAL)])))
        XCTAssertTrue(flows.play())
        XCTAssertEqual(session.flowStatistics()?.muted, 1)
        XCTAssertTrue(session.setRecordsURLPaths(true))
        XCTAssertTrue(session.applyMutes(MuteList()))
        let indicator = Indicator(name: "Flow", description: "", symbol: "star", color: .blue,
                                  predicate: "event.new_flow != nil")
        XCTAssertTrue(session.applyIndicators(CompiledIndicators([indicator])))
        XCTAssertTrue(flows.play())
        let events = try emitted.all.map { try JSONDecoder().decode(Message.self, from: $0.json) }
        XCTAssertEqual(events.map { $0.event.networkFlow?.url },
                       [FlowClientHarness.host, FlowClientHarness.url], "The second flow was muted")
        XCTAssertEqual(events.map { $0.indicators?.hits.map(\.name) ?? [] }, [[], ["Flow"]])
        session.stop()
        XCTAssertFalse(session.setRecordsURLPaths(false), "A stopped session takes no change")
    }

    /// A mute that names only a flow event mutes its process's flows from the start, and no Endpoint Security
    /// client is asked to mute a flow event's type, which Endpoint Security refuses.
    func testAFlowMuteNeverReachesEndpointSecurity() throws {
        var configuration = CaptureConfiguration(events: [MacMonitorEvent.new_flow.type], label: "Test")
        configuration.mutes = MuteList([PathMute(path: "/usr/bin/curl", type: ES_MUTE_PATH_TYPE_LITERAL,
                                                 events: [MacMonitorEvent.new_flow.type])])
        let session = try makeSession(configuration, factory: factory, flows: flows.client, emitted: emitted)
        session.isRecording = true
        XCTAssertTrue(flows.play())
        XCTAssertTrue(emitted.all.isEmpty)
        XCTAssertEqual(session.flowStatistics()?.muted, 1)
        let flowMutes = factory.clients.flatMap(\.calls).filter { call in
            guard case .setPathMute(let mute, _) = call else { return false }
            return mute.events.contains { MacMonitorEvent($0) != nil }
        }
        XCTAssertEqual(flowMutes, [])
    }

    /// Stopping waits for an Endpoint Security event and a flow both still being built by one deadline, not one
    /// after the other.
    func testStopWaitsOnceForEveryLane() throws {
        let building = DispatchSemaphore(value: 0), finish = DispatchSemaphore(value: 0)
        let serializer = StubSerializer { _, _ in
            building.signal()
            finish.wait()
            return Data("late".utf8)
        }
        /// The flow's process has a parent the table knows by its key alone, so the flow reads it from the system.
        let lineage = ProcessLineage(reader: { _ in
            building.signal()
            finish.wait()
            return nil
        }, patience: 0, waitBudget: 0)
        let monitor = LineageMonitor(lineage: lineage, factory: FakeEndpointSecurityClientFactory(), running: { [] })
        let configuration = CaptureConfiguration(events: [ES_EVENT_TYPE_NOTIFY_EXIT, MacMonitorEvent.new_flow.type],
                                                 label: "Test")
        let session = try CaptureSession(configuration, clients: factory, serializer: serializer,
                                         sensorID: { "SENSOR" }, lineage: monitor, flows: flows.client,
                                         emit: emitted.append)
        session.isRecording = true
        session.closeTimeout = .milliseconds(500)
        let key = ProcessKey(pid: 100, pidversion: 7)
        lineage.exec(ProcessProgram(key: key, path: "/usr/bin/curl"), replacing: key,
                     parent: ProcessKey(pid: 600, pidversion: 1), at: 0)
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1), process = factory.client(.process)
        DispatchQueue.global().async { process.deliver(exit) }
        flows.socket?.deliver(flows.flow(), waking: false)
        flows.client.drain {}
        XCTAssertEqual(building.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(building.wait(timeout: .now() + 5), .success)
        let started = Date()
        session.stop()
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.9)
        finish.signal()
        finish.signal()
        XCTAssertTrue(waitUntil { process.calls(.delete).count == 1 })
    }
}
