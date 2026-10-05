//
//  CaptureSessionStartTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Starting a capture session
/// Pins how a capture session starts: one client per class, each muted the same way before it subscribes to its
/// share of the events, and all or nothing when Endpoint Security refuses.
final class CaptureSessionStartTests: XCTestCase {
    /// A configuration with one mute of its own, so tests can tell it from the default set.
    private var configuration: CaptureConfiguration {
        var configuration = CaptureConfiguration(label: "Test")
        configuration.mutes = [PathMute(path: "/tmp/mine", type: ES_MUTE_PATH_TYPE_TARGET_PREFIX)]
        return configuration
    }
    
    /// Every call before a client's first subscription.
    ///
    /// - Parameter client: A fake client.
    /// - Returns: The calls before it, or all of them if it never subscribed.
    private func callsBeforeSubscribing(_ client: FakeEndpointSecurityClient) -> [FakeEndpointSecurityClient.Call] {
        Array(client.calls.prefix { $0.kind != .subscribe })
    }
    
    /// One client is made per class, in ``EventClass/allCases`` order, and each subscribes only to its class's share.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testEachClassGetsItsOwnClient() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let session = try makeSession(configuration, factory: factory)
        XCTAssertEqual(factory.clients.count, CaptureSession.clientsPerSession)
        XCTAssertEqual(CaptureSession.clientsPerSession, 3)
        let split = EventClassTable.split(session.subscribedEvents)
        for (client, eventClass) in zip(factory.clients, EventClass.allCases) {
            XCTAssertEqual(client.calls(.subscribe), [.subscribe(split[eventClass] ?? [])], eventClass.rawValue)
        }
        XCTAssertEqual(session.subscribedEvents.map(\.rawValue),
                       CaptureSession.capturable(defaultEventSubscriptions, label: "").map(\.rawValue))
    }
    
    /// Every client mutes this process before it subscribes.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testEveryClientMutesThisProcessBeforeSubscribing() throws {
        let factory = FakeEndpointSecurityClientFactory()
        _ = try makeSession(configuration, factory: factory)
        for client in factory.clients {
            XCTAssertEqual(callsBeforeSubscribing(client).filter { $0.kind == .muteProcess },
                           [.muteProcess(pid: getpid())])
        }
        
        var unmuted = configuration
        unmuted.mutesSelf = false
        let other = FakeEndpointSecurityClientFactory()
        _ = try makeSession(unmuted, factory: other)
        XCTAssertTrue(other.clients.allSatisfy { $0.calls(.muteProcess).isEmpty })
    }
    
    /// Every client gets the same path mutes, the default set then the configuration's, before it subscribes.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testEveryClientGetsTheSameMutesBeforeSubscribing() throws {
        let factory = FakeEndpointSecurityClientFactory()
        _ = try makeSession(configuration, factory: factory)
        let expected = (MuteSet.default.pathMutes + configuration.mutes).map {
            FakeEndpointSecurityClient.Call.setPathMute($0, muted: true)
        }
        for client in factory.clients {
            XCTAssertEqual(callsBeforeSubscribing(client).filter { $0.kind == .setPathMute }, expected)
            XCTAssertEqual(client.calls(.setPathMute).count, expected.count)
        }
    }
    
    /// Without the default set, only the configuration's mutes are applied.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testDefaultMuteSetCanBeLeftOut() throws {
        var bare = configuration
        bare.appliesDefaultMuteSet = false
        let factory = FakeEndpointSecurityClientFactory()
        _ = try makeSession(bare, factory: factory)
        for client in factory.clients {
            XCTAssertEqual(client.calls(.setPathMute), [.setPathMute(bare.mutes[0], muted: true)])
        }
    }
    
    /// Endpoint Security's default mutes are read from the first client before any of Mac Monitor's are applied.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testAppleMuteSetIsReadBeforeMacMonitorsMutes() throws {
        let apple = [ESMutedPath(type: "ES_MUTE_PATH_TYPE_LITERAL", events: [], path: "/usr/libexec/apple")]
        let factory = FakeEndpointSecurityClientFactory(mutedPaths: [0: apple])
        let session = try makeSession(configuration, factory: factory)
        XCTAssertEqual(session.appleMuteSet, Set(apple.map { pathToJSON(value: $0) }))
        let calls = factory.clients[0].calls
        let read = try XCTUnwrap(calls.firstIndex(of: .mutedPaths))
        let firstMute = try XCTUnwrap(calls.firstIndex { $0.kind == .setPathMute })
        XCTAssertLessThan(read, firstMute)
    }
    
    /// A refused second client throws, and the first is deleted without ever subscribing.
    func testRefusedSecondClientDeletesTheFirst() {
        let factory = FakeEndpointSecurityClientFactory(refusals: [1: .tooManyClients])
        XCTAssertThrowsError(try makeSession(configuration, factory: factory)) { error in
            XCTAssertEqual(error as? CaptureStartError, .clientRefused(.file, .tooManyClients))
            XCTAssertEqual((error as? CaptureStartError)?.clientResult, .tooManyClients)
        }
        XCTAssertEqual(factory.clients.count, 1)
        XCTAssertEqual(factory.clients[0].calls, [.delete])
    }
    
    /// A refused third client throws, and the first two are deleted.
    func testRefusedThirdClientDeletesTheOthers() {
        let factory = FakeEndpointSecurityClientFactory(refusals: [2: .notPermitted])
        XCTAssertThrowsError(try makeSession(configuration, factory: factory)) { error in
            XCTAssertEqual(error as? CaptureStartError, .clientRefused(.memory, .notPermitted))
            XCTAssertEqual((error as? CaptureStartError)?.clientResult, .notPermitted)
        }
        XCTAssertEqual(factory.clients.count, 2)
        XCTAssertTrue(factory.clients.allSatisfy { $0.calls == [.delete] })
    }
    
    /// A refused subscription throws, and every client is unsubscribed then deleted.
    func testFailedSubscriptionTearsEverythingDown() {
        let factory = FakeEndpointSecurityClientFactory(refusing: [1: [.subscribe]])
        XCTAssertThrowsError(try makeSession(configuration, factory: factory)) { error in
            XCTAssertEqual(error as? CaptureStartError, .subscriptionFailed(.file))
            XCTAssertEqual((error as? CaptureStartError)?.clientResult, .internalSubsystem)
        }
        XCTAssertEqual(factory.clients.count, 3)
        for client in factory.clients {
            XCTAssertEqual(client.calls.suffix(2), [.unsubscribeAll, .delete])
            XCTAssertEqual(client.calls(.delete).count, 1)
        }
        XCTAssertTrue(factory.clients[2].calls(.subscribe).isEmpty)
    }
    
    /// AUTH events, unknown names, events Mac Monitor doesn't model, and repeats are left out; the rest keep their
    /// order.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testUnmodeledEventsAreLeftOut() throws {
        var requested = configuration
        requested.events = [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_LAST,
                            ES_EVENT_TYPE_NOTIFY_STAT, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_OPEN]
        let factory = FakeEndpointSecurityClientFactory()
        let session = try makeSession(requested, factory: factory)
        XCTAssertEqual(session.subscribedEvents, [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertEqual(factory.clients[0].calls(.subscribe), [.subscribe([ES_EVENT_TYPE_NOTIFY_EXEC])])
        XCTAssertEqual(factory.clients[1].calls(.subscribe), [.subscribe([ES_EVENT_TYPE_NOTIFY_OPEN])])
        XCTAssertEqual(factory.clients[2].calls(.subscribe), [.subscribe([])])
    }
    
    /// A class with no events starts even though its client would refuse a subscription: an empty share succeeds
    /// without asking Endpoint Security, as the live client's does.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testAClassWithNoEventsNeedsNoSubscription() throws {
        var requested = configuration
        requested.events = [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_OPEN]
        let factory = FakeEndpointSecurityClientFactory(refusing: [2: [.subscribe]])
        let session = try makeSession(requested, factory: factory)
        XCTAssertEqual(session.subscribedEvents, [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_OPEN])
        XCTAssertEqual(factory.clients[2].calls(.subscribe), [.subscribe([])])
    }
    
    /// A new session serializes nothing until it's told to record.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func testNewSessionIsNotRecording() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        var serialized = 0
        let serializer = StubSerializer { _, _ in serialized += 1; return Data() }
        let session = try makeSession(configuration, factory: factory, serializer: serializer, emitted: emitted)
        factory.clients[0].deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, global: 1))
        XCTAssertFalse(session.isRecording)
        XCTAssertEqual(serialized, 0)
        XCTAssertTrue(emitted.all.isEmpty)
    }
}
