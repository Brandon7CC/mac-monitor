//
//  CaptureSessionDrainTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Draining a session
/// Pins how a stopping stream keeps what it captured: every client stops queueing messages and syncs, and the drain
/// completes on the session's queue after every event emitted before each client's marker.
final class CaptureSessionDrainTests: XCTestCase {
    private let queue = DispatchQueue(label: "CaptureSessionDrainTests")
    /// What reached the session's queue, in order: events by `global_seq_num`, and "drained".
    private let arrivals = Recorded<String>()
    
    /// A recording session whose events hop onto ``queue``, as a stream's do.
    ///
    /// - Parameter factory: Makes the fake clients.
    /// - Returns: The session.
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    private func makeSession(_ factory: FakeEndpointSecurityClientFactory) throws -> CaptureSession {
        let session = try CaptureSession(CaptureConfiguration(label: "Test"), clients: factory,
                                         serializer: StubSerializer.globalSequence, sensorID: { "SENSOR" },
                                         emit: { [queue, arrivals] event in
            queue.async { arrivals.append(String(decoding: event.json, as: UTF8.self)) }
        })
        session.isRecording = true
        return session
    }
    
    /// Start a drain on the session's queue.
    ///
    /// - Parameter session: The session.
    private func drain(_ session: CaptureSession) {
        queue.sync {
            session.drain(on: queue) { [arrivals] in arrivals.append("drained") }
        }
    }
    
    /// What reached the queue, once it has seen this many drains complete.
    ///
    /// - Parameter drains: How many drains to wait for.
    /// - Returns: The arrivals.
    private func arrivals(after drains: Int = 1) -> [String] {
        XCTAssertTrue(waitUntil { arrivals.all.filter { $0 == "drained" }.count >= drains })
        return queue.sync { arrivals.all }
    }
    
    /// Every client is unsubscribed from everything and then synced, and the drain completes after every event
    /// handled before the markers came up, including one handled after the drain started.
    func testDrainCompletesAfterEveryEventAheadOfTheMarkers() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try makeSession(factory)
        factory.clients.forEach { $0.holdSyncs() }
        factory.client(.process).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1))
        drain(session)
        for client in factory.clients {
            XCTAssertEqual(Array(client.calls.suffix(2)), [.unsubscribeAll, .sync])
        }
        /// Queued before the marker, handled after the drain started.
        factory.client(.process).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 2))
        factory.client(.file).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_OPEN, global: 1))
        factory.clients.forEach { $0.releaseSyncs() }
        XCTAssertEqual(arrivals(), ["1", "2", "1", "drained"])
    }
    
    /// The drain waits for the last client's marker.
    func testDrainWaitsForEveryClient() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try makeSession(factory)
        factory.clients.forEach { $0.holdSyncs() }
        drain(session)
        factory.client(.process).releaseSyncs()
        factory.client(.memory).releaseSyncs()
        queue.sync {}
        XCTAssertEqual(arrivals.all, [])
        factory.client(.file).releaseSyncs()
        XCTAssertEqual(arrivals(), ["drained"])
    }
    
    /// Without `es_sync_client` (before macOS 27) the drain only unsubscribes, and completes right away.
    func testDrainWithoutSyncCompletesRightAway() throws {
        let factory = FakeEndpointSecurityClientFactory(refusing: [0: [.sync], 1: [.sync], 2: [.sync]])
        let session = try makeSession(factory)
        drain(session)
        XCTAssertEqual(arrivals(), ["drained"])
        XCTAssertTrue(factory.clients.allSatisfy { $0.calls(.unsubscribeAll).count == 1 })
    }
    
    /// A stopped session has nothing to drain. A session stopped mid-drain still completes it: deleting a client
    /// calls its sync blocks.
    func testStoppedSessionsComplete() throws {
        let stopped = try makeSession(FakeEndpointSecurityClientFactory())
        queue.sync { stopped.stop() }
        drain(stopped)
        XCTAssertEqual(arrivals(), ["drained"])
        
        let factory = FakeEndpointSecurityClientFactory()
        let draining = try makeSession(factory)
        factory.clients.forEach { $0.holdSyncs() }
        drain(draining)
        queue.sync { draining.stop() }
        XCTAssertEqual(arrivals(after: 2), ["drained", "drained"])
    }
}
