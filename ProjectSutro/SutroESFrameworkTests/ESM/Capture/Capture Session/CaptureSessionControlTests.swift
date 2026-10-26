//
//  CaptureSessionControlTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Controlling a capture session
/// Pins a running capture session: subscriptions go to the client of their class, mutes go to every client, and each
/// lane emits its client's events in order while recording.
final class CaptureSessionControlTests: XCTestCase {
    private let factory = FakeEndpointSecurityClientFactory()
    /// What the session emitted.
    private let emitted = EmittedEvents()
    
    /// Calls made after the session started.
    ///
    /// - Parameters:
    ///   - client: A fake client.
    ///   - start: How many calls it had when the session started.
    /// - Returns: The calls since.
    private func callsSince(_ start: Int, on client: FakeEndpointSecurityClient) -> [FakeEndpointSecurityClient.Call] {
        Array(client.calls.dropFirst(start))
    }
    
    /// A runtime (un)subscription reaches only the client of the event's class.
    func testSubscriptionGoesToItsClassClient() throws {
        let session = try makeSession(factory: factory)
        let process = factory.client(.process), file = factory.client(.file), memory = factory.client(.memory)
        let processStart = process.calls.count, fileStart = file.calls.count, memoryStart = memory.calls.count
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_OPEN, enabled: true))
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_EXEC, enabled: false))
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_MPROTECT, enabled: true))
        XCTAssertEqual(callsSince(processStart, on: process), [.unsubscribe([ES_EVENT_TYPE_NOTIFY_EXEC])])
        XCTAssertEqual(callsSince(fileStart, on: file), [.subscribe([ES_EVENT_TYPE_NOTIFY_OPEN])])
        XCTAssertEqual(callsSince(memoryStart, on: memory), [.subscribe([ES_EVENT_TYPE_NOTIFY_MPROTECT])])
    }
    
    /// Subscribing adds an event once, unsubscribing removes it, and a refused request changes nothing.
    func testSubscriptionBookkeeping() throws {
        var configuration = CaptureConfiguration(label: "Test")
        configuration.events = [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK]
        let session = try makeSession(configuration, factory: factory)
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_EXEC, enabled: true))
        XCTAssertEqual(session.subscribedEvents, [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK])
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_OPEN, enabled: true))
        XCTAssertTrue(session.setSubscription(ES_EVENT_TYPE_NOTIFY_EXEC, enabled: false))
        XCTAssertEqual(session.subscribedEvents, [ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_OPEN])
        
        factory.client(.file).setRefusing(.subscribe, true)
        XCTAssertFalse(session.setSubscription(ES_EVENT_TYPE_NOTIFY_CLOSE, enabled: true))
        factory.client(.process).setRefusing(.unsubscribe, true)
        XCTAssertFalse(session.setSubscription(ES_EVENT_TYPE_NOTIFY_FORK, enabled: false))
        XCTAssertEqual(session.subscribedEvents, [ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_OPEN])
    }
    
    /// Events Mac Monitor doesn't model are refused without a call to Endpoint Security.
    func testUnmodeledSubscriptionsAreRefused() throws {
        let session = try makeSession(factory: factory)
        let started = factory.clients.map(\.calls.count)
        for event in [ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_LAST, ES_EVENT_TYPE_NOTIFY_STAT] {
            XCTAssertFalse(session.setSubscription(event, enabled: true), "\(event.rawValue)")
            XCTAssertFalse(session.setSubscription(event, enabled: false), "\(event.rawValue)")
        }
        XCTAssertEqual(factory.clients.map(\.calls.count), started)
    }
    
    /// Applying a list sends every client only what changed since the last one: new events muted first, then old
    /// ones unmuted, key by key in canonical order.
    func testApplyMutesSendsOnlyTheDifference() throws {
        let session = try makeSession(factory: factory)
        let open = ES_EVENT_TYPE_NOTIFY_OPEN, close = ES_EVENT_TYPE_NOTIFY_CLOSE
        let first = MuteList([PathMute(path: "/tmp/x", type: ES_MUTE_PATH_TYPE_PREFIX, events: [open]),
                              PathMute(path: "/gone", type: ES_MUTE_PATH_TYPE_LITERAL)])
        XCTAssertTrue(session.applyMutes(first))
        let started = factory.clients.map(\.calls.count)
        let second = MuteList([PathMute(path: "/tmp/x", type: ES_MUTE_PATH_TYPE_PREFIX, events: [close]),
                               PathMute(path: "/new", type: ES_MUTE_PATH_TYPE_TARGET_LITERAL)])
        XCTAssertTrue(session.applyMutes(second))
        XCTAssertTrue(session.applyMutes(second))
        let expected: [FakeEndpointSecurityClient.Call] = [
            .setPathMute(PathMute(path: "/gone", type: ES_MUTE_PATH_TYPE_LITERAL), muted: false),
            .setPathMute(PathMute(path: "/tmp/x", type: ES_MUTE_PATH_TYPE_PREFIX, events: [close]), muted: true),
            .setPathMute(PathMute(path: "/tmp/x", type: ES_MUTE_PATH_TYPE_PREFIX, events: [open]), muted: false),
            .setPathMute(PathMute(path: "/new", type: ES_MUTE_PATH_TYPE_TARGET_LITERAL), muted: true)
        ]
        for (client, start) in zip(factory.clients, started) {
            XCTAssertEqual(callsSince(start, on: client), expected)
        }
        XCTAssertEqual(session.appliedMutes, second)
    }
    
    /// One client's refusal is reported, the others still take the change, and the session counts the list as
    /// applied, so the same list again sends nothing.
    func testApplyMutesReportsAPartialRefusal() throws {
        let session = try makeSession(factory: factory)
        let started = factory.clients.map(\.calls.count)
        factory.client(.memory).setRefusing(.setPathMute, true)
        let mute = PathMute(path: "/tmp/x", type: ES_MUTE_PATH_TYPE_LITERAL)
        XCTAssertFalse(session.applyMutes(MuteList([mute])))
        XCTAssertTrue(session.applyMutes(MuteList([mute])))
        for (client, start) in zip(factory.clients, started) {
            XCTAssertEqual(callsSince(start, on: client), [.setPathMute(mute, muted: true)])
        }
    }
    
    /// Applying Mac Monitor's default set to a session without mutes mutes each of its events on every client.
    func testApplyingTheDefaultSetGoesToEveryClient() throws {
        let session = try makeSession(factory: factory)
        let started = factory.clients.map(\.calls.count)
        XCTAssertTrue(session.applyMutes(.testDefault))
        let expected = MuteList().changes(to: .testDefault).map {
            FakeEndpointSecurityClient.Call.setPathMute($0.mute, muted: true)
        }
        for (client, start) in zip(factory.clients, started) {
            XCTAssertEqual(callsSince(start, on: client), expected)
        }
    }
    
    /// Events are serialized only while recording, each tagged with its lane's class and stamped with the current
    /// Sensor ID.
    func testRecordingGateAndSensorID() throws {
        var sensorIDs = ["S1", "S2"].makeIterator()
        let serializer = StubSerializer { _, lane in Data("\(lane.eventClass.rawValue) \(lane.sensorID)".utf8) }
        let session = try makeSession(factory: factory, serializer: serializer, sensorID: { sensorIDs.next() ?? "" },
                                      emitted: emitted)
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1)
        let open = sequencedMessage(ES_EVENT_TYPE_NOTIFY_OPEN, global: 1)
        
        session.isRecording = true
        factory.client(.process).deliver(exit)
        session.refreshSensorID()
        factory.client(.file).deliver(open)
        session.isRecording = false
        factory.client(.process).deliver(exit)
        
        let events = emitted.all
        XCTAssertEqual(events.map(\.eventClass), [.process, .file])
        XCTAssertEqual(events.map { String(decoding: $0.json, as: UTF8.self) }, ["process S1", "file S2"])
    }
    
    /// Turning recording off and on and changing the Sensor ID don't wait for an event being built, which still goes
    /// out with the Sensor ID it started with.
    func testControlNeverWaitsForAnEventBeingBuilt() throws {
        let building = DispatchSemaphore(value: 0)
        let finish = DispatchSemaphore(value: 0)
        var sensorIDs = ["S1", "S2"].makeIterator()
        let serializer = StubSerializer { _, lane in
            building.signal()
            finish.wait()
            return Data(lane.sensorID.utf8)
        }
        let session = try makeSession(factory: factory, serializer: serializer, sensorID: { sensorIDs.next() ?? "" },
                                      emitted: emitted)
        session.isRecording = true
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1)
        let process = factory.client(.process)
        let delivered = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            process.deliver(exit)
            delivered.signal()
        }
        XCTAssertEqual(building.wait(timeout: .now() + 5), .success)
        
        let controlled = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            session.isRecording = false
            session.refreshSensorID()
            session.isRecording = true
            controlled.signal()
        }
        XCTAssertEqual(controlled.wait(timeout: .now() + 5), .success)
        finish.signal()
        XCTAssertEqual(delivered.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(emitted.all.map { String(decoding: $0.json, as: UTF8.self) }, ["S1"])
    }
    
    /// Delivered from three threads at once, each class's events leave its lane in its client's order.
    func testLanesKeepTheirOrderUnderConcurrentDelivery() throws {
        let session = try makeSession(factory: factory, emitted: emitted)
        session.isRecording = true
        let types = [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_MMAP]
        let fixtures = types.map { sequencedMessage($0, global: 0) }
        let clients = factory.clients
        DispatchQueue.concurrentPerform(iterations: clients.count) { index in
            for global in 1...500 {
                fixtures[index].message.pointee.global_seq_num = UInt64(global)
                clients[index].deliver(fixtures[index])
            }
        }
        for eventClass in EventClass.allCases {
            XCTAssertEqual(emitted.globalSequences(of: eventClass), Array(1...500), eventClass.rawValue)
        }
    }
    
    /// An event that can't be serialized is skipped, and the next one still goes out.
    func testUnserializableEventsAreSkipped() throws {
        let serializer = StubSerializer { message, _ in
            message.pointee.global_seq_num == 1 ? nil : Data("\(message.pointee.global_seq_num)".utf8)
        }
        let session = try makeSession(factory: factory, serializer: serializer, emitted: emitted)
        session.isRecording = true
        factory.client(.process).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1))
        factory.client(.process).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 2))
        XCTAssertEqual(emitted.globalSequences(of: .process), [2])
    }
}
