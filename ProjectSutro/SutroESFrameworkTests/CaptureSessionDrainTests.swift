//
//  CaptureSessionDrainTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
import os
@testable import SutroESFramework


// MARK: - Draining a session
/// Pins how a stopping stream keeps what it captured: every client stops queueing messages and syncs, and the drain
/// completes on the session's queue after every event emitted before each client's marker.
final class CaptureSessionDrainTests: XCTestCase {
    private let queue = DispatchQueue(label: "CaptureSessionDrainTests")
    /// What reached the session's queue, in order: events by `global_seq_num`, and "drained".
    private let arrivals = OSAllocatedUnfairLock<[String]>(initialState: [])
    
    /// A recording session whose events hop onto ``queue``, as a stream's do.
    ///
    /// - Parameter factory: Makes the fake clients.
    /// - Returns: The session.
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    private func makeSession(_ factory: FakeEndpointSecurityClientFactory) throws -> CaptureSession {
        let session = try CaptureSession(CaptureConfiguration(label: "Test"), clients: factory,
                                         serializer: StubSerializer.globalSequence, sensorID: { "SENSOR" },
                                         emit: { [queue, arrivals] event in
            queue.async { arrivals.withLock { $0.append(String(decoding: event.json, as: UTF8.self)) } }
        })
        session.isRecording = true
        return session
    }
    
    /// Start a drain on the session's queue.
    ///
    /// - Parameter session: The session.
    private func drain(_ session: CaptureSession) {
        queue.sync {
            session.drain(on: queue) { [arrivals] in arrivals.withLock { $0.append("drained") } }
        }
    }
    
    /// Every client is unsubscribed from everything and then synced, and the drain completes after every event
    /// handled before the markers came up, including one handled after the drain started.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testDrainCompletesAfterEveryEventAheadOfTheMarkers() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try makeSession(factory)
        factory.clients.forEach { $0.holdSyncs() }
        factory.clients[0].deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1))
        drain(session)
        for client in factory.clients {
            XCTAssertEqual(Array(client.calls.suffix(2)), [.unsubscribeAll, .sync])
        }
        /// Queued before the marker, handled after the drain started.
        factory.clients[0].deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 2))
        factory.clients[1].deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_OPEN, global: 1))
        factory.clients.forEach { $0.releaseSyncs() }
        queue.sync {}
        XCTAssertEqual(arrivals.withLock { $0 }, ["1", "2", "1", "drained"])
    }
    
    /// The drain waits for the last client's marker.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testDrainWaitsForEveryClient() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try makeSession(factory)
        factory.clients.forEach { $0.holdSyncs() }
        drain(session)
        factory.clients[0].releaseSyncs()
        factory.clients[2].releaseSyncs()
        queue.sync {}
        XCTAssertEqual(arrivals.withLock { $0 }, [])
        factory.clients[1].releaseSyncs()
        queue.sync {}
        XCTAssertEqual(arrivals.withLock { $0 }, ["drained"])
    }
    
    /// Without `es_sync_client` (before macOS 27) the drain only unsubscribes, and completes right away.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testDrainWithoutSyncCompletesRightAway() throws {
        let factory = FakeEndpointSecurityClientFactory(refusing: [0: [.sync], 1: [.sync], 2: [.sync]])
        let session = try makeSession(factory)
        drain(session)
        queue.sync {}
        XCTAssertEqual(arrivals.withLock { $0 }, ["drained"])
        XCTAssertTrue(factory.clients.allSatisfy { $0.calls(.unsubscribeAll).count == 1 })
    }
    
    /// A stopped session has nothing to drain. A session stopped mid-drain still completes it: deleting a client
    /// calls its sync blocks.
    ///
    /// - Throws: ``CaptureStartError`` if a session couldn't start.
    func testStoppedSessionsComplete() throws {
        let stopped = try makeSession(FakeEndpointSecurityClientFactory())
        queue.sync { stopped.stop() }
        drain(stopped)
        queue.sync {}
        XCTAssertEqual(arrivals.withLock { $0 }, ["drained"])
        
        let factory = FakeEndpointSecurityClientFactory()
        let draining = try makeSession(factory)
        factory.clients.forEach { $0.holdSyncs() }
        drain(draining)
        queue.sync { draining.stop() }
        queue.sync {}
        XCTAssertEqual(arrivals.withLock { $0 }, ["drained", "drained"])
    }
    
    /// `es_sync_client` is found on macOS 27, where it was introduced.
    func testTheLiveClientFindsSyncOnMacOS27() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.isOperatingSystemAtLeast(
            OperatingSystemVersion(majorVersion: 27, minorVersion: 0, patchVersion: 0)))
        XCTAssertTrue(LiveEndpointSecurityClient.supportsSync)
    }
}
