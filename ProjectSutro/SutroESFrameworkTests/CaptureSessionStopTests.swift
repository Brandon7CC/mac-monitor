//
//  CaptureSessionStopTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Stopping a capture session
/// Pins how a capture session stops: every client is unsubscribed, then deleted once no event is being built, so
/// `es_delete_client` never overlaps another call on its client.
final class CaptureSessionStopTests: XCTestCase {
    /// Stopping unsubscribes every client and then deletes it, once; stopping again does nothing.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testStopUnsubscribesThenDeletesOnce() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try makeSession(factory: factory)
        session.stop()
        session.stop()
        for client in factory.clients {
            XCTAssertEqual(client.calls.suffix(2), [.unsubscribeAll, .delete])
            XCTAssertEqual(client.calls(.unsubscribeAll).count, 1)
            XCTAssertEqual(client.calls(.delete).count, 1)
        }
    }
    
    /// Stopping waits for an event being built before it deletes any client, and nothing is emitted once it returns.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testStopWaitsForAnEventBeingBuilt() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let building = DispatchSemaphore(value: 0)
        let finish = DispatchSemaphore(value: 0)
        let serializer = StubSerializer { _, _ in
            building.signal()
            finish.wait()
            return Data("built".utf8)
        }
        let session = try makeSession(factory: factory, serializer: serializer, emitted: emitted)
        session.isRecording = true
        session.closeTimeout = .seconds(30)
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1)
        let process = factory.clients[0]
        DispatchQueue.global().async { process.deliver(exit) }
        XCTAssertEqual(building.wait(timeout: .now() + 5), .success)
        
        let stopped = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            session.stop()
            stopped.signal()
        }
        XCTAssertEqual(stopped.wait(timeout: .now() + 0.2), .timedOut)
        XCTAssertTrue(factory.clients.allSatisfy { $0.calls(.delete).isEmpty })
        
        finish.signal()
        XCTAssertEqual(stopped.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(factory.clients.allSatisfy { $0.calls(.delete).count == 1 })
        XCTAssertEqual(emitted.all.count, 1)
    }
    
    /// An event that outlasts the deadline doesn't hold up stopping: the other clients are deleted at once, the slow
    /// lane's client once its event is done, and that event is dropped rather than emitted after the session stopped.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testStopGivesUpOnASlowEvent() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let building = DispatchSemaphore(value: 0)
        let finish = DispatchSemaphore(value: 0)
        let serializer = StubSerializer { _, _ in
            building.signal()
            finish.wait()
            return Data("late".utf8)
        }
        let session = try makeSession(factory: factory, serializer: serializer, emitted: emitted)
        session.isRecording = true
        session.closeTimeout = .milliseconds(100)
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1)
        let process = factory.clients[0]
        let delivered = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            process.deliver(exit)
            delivered.signal()
        }
        XCTAssertEqual(building.wait(timeout: .now() + 5), .success)
        
        session.stop()
        XCTAssertTrue(process.calls(.delete).isEmpty)
        XCTAssertTrue(factory.clients.dropFirst().allSatisfy { $0.calls(.delete).count == 1 })
        
        finish.signal()
        XCTAssertEqual(delivered.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(waitUntil { process.calls(.delete).count == 1 })
        XCTAssertEqual(process.calls.suffix(2), [.unsubscribeAll, .delete])
        XCTAssertTrue(emitted.all.isEmpty)
    }
    
    /// A message Endpoint Security still hands over after the session stopped is ignored.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testMessagesAfterStopAreIgnored() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        var serialized = 0
        let serializer = StubSerializer { _, _ in serialized += 1; return Data() }
        let session = try makeSession(factory: factory, serializer: serializer, emitted: emitted)
        session.isRecording = true
        let handler = try XCTUnwrap(factory.clients[0].handler)
        session.stop()
        session.isRecording = true
        handler(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1).raw)
        XCTAssertEqual(serialized, 0)
        XCTAssertTrue(emitted.all.isEmpty)
    }
    
    /// After stopping, control calls fail without reaching Endpoint Security.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testControlCallsAfterStopDoNothing() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try makeSession(factory: factory)
        session.stop()
        let stopped = factory.clients.map(\.calls.count)
        XCTAssertFalse(session.setSubscription(ES_EVENT_TYPE_NOTIFY_OPEN, enabled: true))
        XCTAssertFalse(session.applyMutes(MuteList([PathMute(path: "/tmp/x", type: ES_MUTE_PATH_TYPE_LITERAL)])))
        XCTAssertFalse(session.applyMutes(.testDefault))
        XCTAssertTrue(session.mutedPaths().isEmpty)
        XCTAssertEqual(factory.clients.map(\.calls.count), stopped)
    }
    
    /// A session released without being stopped still unsubscribes and deletes every client.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testReleasingASessionStopsIt() throws {
        let factory = FakeEndpointSecurityClientFactory()
        var session: CaptureSession? = try makeSession(factory: factory)
        XCTAssertNotNil(session)
        session = nil
        for client in factory.clients {
            XCTAssertEqual(client.calls.suffix(2), [.unsubscribeAll, .delete])
        }
    }
}
