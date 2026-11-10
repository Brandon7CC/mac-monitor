//
//  SensorServiceHarness.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - In-process Security Extension for Mac Monitor
/// The Security Extension's side of Mac Monitor, in the test process: the real ``SensorService`` on an anonymous NSXPC
/// listener, capturing on fake Endpoint Security clients with a fake updater. Only Endpoint Security itself, root,
/// the router and the code signing requirements are left out.
final class SensorServiceHarness: NSObject, NSXPCListenerDelegate {
    let service: SensorService
    let updates: FakeUpdater
    private let listener = NSXPCListener.anonymous()
    /// Each capture session's client factory, in the order the service asked for them.
    private let madeFactories = Recorded<FakeEndpointSecurityClientFactory>()
    /// How many times the owner went away, each of which posts the released notification in the Security Extension.
    private let releaseCount = OSAllocatedUnfairLock(initialState: 0)
    /// How many times a Sensor ID was computed: once when capture starts, and once on each later handshake.
    private let sensorIDCount = OSAllocatedUnfairLock(initialState: 0)
    /// The service's side of every connection, in the order they were accepted.
    private let accepted = Recorded<NSXPCConnection>()
    /// How many of them the service saw go away.
    private let invalidationCount = OSAllocatedUnfairLock(initialState: 0)

    /// - Parameters:
    ///   - savedMutes: The saved mute set.
    ///   - savedIndicators: The Mac's indicator set.
    ///   - commandLineAccess: Who may use `macmonitor` without `sudo`.
    ///   - refusals: `es_new_client` refusals for each capture session the service starts, by client:
    ///     `[[0: .tooManyClients]]` refuses the first session's first client, and later sessions start.
    init(savedMutes: SavedMuteSet, savedIndicators: SavedIndicatorSet, commandLineAccess: CommandLineAccessStore,
         refusals: [[Int: NewClientResult]] = []) {
        let (updater, pending) = (FakeUpdater(), OSAllocatedUnfairLock(uncheckedState: refusals))
        let (made, releases, sensorIDs) = (madeFactories, releaseCount, sensorIDCount)
        updates = updater
        service = SensorService(savedMutes: savedMutes, savedIndicators: savedIndicators,
                                commandLineAccess: commandLineAccess, updates: updater, makeCapture: { setup, emit in
            let refused = pending.withLockUnchecked { $0.isEmpty ? [:] : $0.removeFirst() }
            let factory = FakeEndpointSecurityClientFactory(refusals: refused)
            made.append(factory)
            return try CaptureSession(setup, clients: factory, serializer: StubSerializer.globalSequence,
                                      sensorID: { sensorIDs.withLock { $0 += 1 }; return "SENSOR" }, emit: emit)
        }, released: { releases.withLock { $0 += 1 } })
        super.init()
        listener.delegate = self
        listener.activate()
    }

    /// Each capture session's client factory, in order, including those Endpoint Security refused.
    var factories: [FakeEndpointSecurityClientFactory] {
        madeFactories.all
    }

    /// How many times the owner went away.
    var releases: Int {
        releaseCount.withLock { $0 }
    }

    /// How many times a Sensor ID was computed.
    var sensorIDs: Int {
        sensorIDCount.withLock { $0 }
    }

    /// The service's side of each connection, in the order each sent its first message.
    var connections: [NSXPCConnection] {
        accepted.all
    }

    /// How many connections the service has finished handling the end of: their invalidation reached the service,
    /// and it has torn down whatever that called for.
    var invalidations: Int {
        let count = invalidationCount.withLock { $0 }
        service.queue.sync {}
        return count
    }

    /// The service's side of the connection that owns the event stream, if any.
    var owner: NSXPCConnection? {
        service.queue.sync { service.sink?.connection }
    }

    /// Is capture running, and recording?
    var capture: (running: Bool, recording: Bool) {
        service.queue.sync { (service.capture != nil, service.capture?.isRecording == true) }
    }

    /// A new connection to the service, as Mac Monitor makes one.
    ///
    /// - Parameter agent: Mac Monitor's side, which receives events and an update's progress.
    /// - Returns: The activated connection.
    func connect(agent: AppAgentProtocol = RecordingAgent()) -> NSXPCConnection {
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = SensorXPC.sensorInterface
        connection.exportedInterface = SensorXPC.agentInterface
        connection.exportedObject = agent
        connection.activate()
        return connection
    }

    /// Hand each new connection to the service, as the router does with Mac Monitor's, and count its end after the
    /// service's own handler has queued what it does.
    ///
    /// - Parameters:
    ///   - listener: The anonymous listener.
    ///   - connection: The new connection.
    /// - Returns: Always `true`.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        accepted.append(connection)
        service.accept(connection)
        let (handler, count) = (connection.invalidationHandler, invalidationCount)
        connection.invalidationHandler = {
            handler?()
            count.withLock { $0 += 1 }
        }
        return true
    }
}


// MARK: - Mac Monitor's side
/// Mac Monitor's ``AppAgentProtocol`` in a test: it keeps every event and every update progress, and replies to
/// each batch at once.
final class RecordingAgent: NSObject, AppAgentProtocol {
    private let events = Recorded<String>()
    private let progress = Recorded<UpdateProgress?>()

    /// Every event received, in order, as text.
    var received: [String] {
        events.all
    }

    /// Every update progress received, in order: `nil` for one that didn't read.
    var updates: [UpdateProgress?] {
        progress.all
    }

    /// Keep a batch, and reply.
    ///
    /// - Parameters:
    ///   - events: The batch.
    ///   - reply: The batch's reply.
    func receive(events: [Data], reply: @escaping () -> Void) {
        events.forEach { self.events.append(String(decoding: $0, as: UTF8.self)) }
        reply()
    }

    /// Keep an update's progress.
    ///
    /// - Parameter progress: A JSON encoded ``UpdateProgress``.
    func updateProgress(_ progress: Data) {
        self.progress.append(try? JSONDecoder().decode(UpdateProgress.self, from: progress))
    }
}


// MARK: - Updater
/// The Security Extension's updater in a test: it counts checks and installs, reports one step of progress, and
/// installs nothing.
final class FakeUpdater: SensorUpdating {
    private let counts = OSAllocatedUnfairLock(initialState: (checks: 0, installs: 0))

    /// How many checks and installs were asked for.
    var asked: (checks: Int, installs: Int) {
        counts.withLock { $0 }
    }

    /// Answer that this is the latest release.
    ///
    /// - Parameter reply: Receives ``UpdateCheck/upToDate``.
    func check(reply: @escaping (Data?) -> Void) {
        counts.withLock { $0.checks += 1 }
        reply(try? JSONEncoder().encode(UpdateCheck.upToDate))
    }

    /// Report the verifying step, then that the release was installed.
    ///
    /// - Parameters:
    ///   - progress: Receives ``UpdateProgress/verifying``.
    ///   - reply: Receives `nil`.
    func install(progress: @escaping (UpdateProgress) -> Void, reply: @escaping (UpdateFailure?) -> Void) {
        counts.withLock { $0.installs += 1 }
        progress(.verifying)
        reply(nil)
    }
}


// MARK: - Requests
extension NSXPCConnection {
    /// Send a ``SensorProtocol`` request and wait for the reply.
    ///
    /// - Parameters:
    ///   - timeout: How long to wait.
    ///   - request: Sends the request to the proxy with the reply block it's given.
    /// - Returns: The reply, or `nil` if none came.
    func sensor<Reply>(timeout: TimeInterval = 5,
                       _ request: (SensorProtocol, @escaping (Reply) -> Void) -> Void) -> Reply? {
        let replied = DispatchSemaphore(value: 0)
        let reply = OSAllocatedUnfairLock<Reply?>(uncheckedState: nil)
        let proxy = remoteObjectProxyWithErrorHandler { _ in replied.signal() }
        guard let sensor = proxy as? SensorProtocol else { return nil }
        request(sensor) { answer in
            reply.withLockUnchecked { $0 = answer }
            replied.signal()
        }
        _ = replied.wait(timeout: .now() + timeout)
        return reply.withLockUnchecked { $0 }
    }

    /// Mac Monitor's handshake.
    ///
    /// - Parameter recording: Whether capture records events.
    /// - Returns: The Security Extension's answer, or `nil` if none came.
    func handshake(recording: Bool = true) -> NewClientResult? {
        sensor { $0.start(recording: recording, reply: $1) }
    }
}
