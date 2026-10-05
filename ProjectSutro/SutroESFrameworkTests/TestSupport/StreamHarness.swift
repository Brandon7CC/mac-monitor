//
//  StreamHarness.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - In-process Security Extension
/// The Security Extension's side of `macmonitor`, in the test process: a ``StreamService`` on an anonymous NSXPC
/// listener whose streams capture on fake Endpoint Security clients. Only Endpoint Security itself, root, and the code
/// signing requirements are left out.
final class StreamHarness: NSObject, NSXPCListenerDelegate {
    let service: StreamService
    private let listener = NSXPCListener.anonymous()
    /// Each started stream's client factory, in the order the streams started.
    private let madeFactories = OSAllocatedUnfairLock<[FakeEndpointSecurityClientFactory]>(uncheckedState: [])
    /// How many streams that held clients have closed.
    private let releaseCount = OSAllocatedUnfairLock(initialState: 0)
    /// The service's side of every connection, in the order they were accepted.
    private let accepted = OSAllocatedUnfairLock<[NSXPCConnection]>(uncheckedState: [])
    
    /// - Parameters:
    ///   - savedMutes: The saved mute set.
    ///   - capacity: The most streams at once.
    ///   - admits: Treat every caller as root?
    ///   - refusals: `es_new_client` refusals for every stream, by client: `[0: .tooManyClients]` refuses the first.
    ///   - serializer: Builds each event's JSON.
    init(savedMutes: SavedMuteSet, capacity: Int = SensorXPC.maxCommandLineStreams, admits: Bool = true,
         refusals: [Int: NewClientResult] = [:], serializer: any EventSerializing = StubSerializer.globalSequence) {
        let (made, releases) = (madeFactories, releaseCount)
        service = StreamService(savedMutes: savedMutes, slots: StreamSlots(capacity: capacity),
                                sensorVersion: "2.2.0 (1)", admits: { _ in admits },
                                makeCapture: { configuration, emit in
            let factory = FakeEndpointSecurityClientFactory(refusals: refusals)
            made.withLockUnchecked { $0.append(factory) }
            return try CaptureSession(configuration, clients: factory, serializer: serializer,
                                      sensorID: { "SENSOR" }, emit: emit)
        }, released: { releases.withLock { $0 += 1 } })
        super.init()
        listener.delegate = self
        listener.activate()
    }
    
    /// Each started stream's client factory, in order.
    var factories: [FakeEndpointSecurityClientFactory] {
        madeFactories.withLockUnchecked { $0 }
    }
    
    /// How many streams that held Endpoint Security clients have closed, each of which posts the released
    /// notification in the Security Extension.
    var releases: Int {
        releaseCount.withLock { $0 }
    }
    
    /// Where `macmonitor` connects.
    var endpoint: NSXPCListenerEndpoint {
        listener.endpoint
    }
    
    /// Drop every connection from the service's side, as a Security Extension that exits does.
    func dropConnections() {
        accepted.withLockUnchecked { $0 }.forEach { $0.invalidate() }
    }
    
    /// A new connection to the service, as `macmonitor` makes one: it exports `reader` for the events.
    ///
    /// - Parameter reader: Receives the stream's batches.
    /// - Returns: The activated connection.
    func connect(reader: StreamReaderProtocol) -> NSXPCConnection {
        let connection = NSXPCConnection(listenerEndpoint: listener.endpoint)
        connection.remoteObjectInterface = SensorXPC.streamInterface
        connection.exportedInterface = SensorXPC.streamReaderInterface
        connection.exportedObject = reader
        connection.activate()
        return connection
    }
    
    /// Hand each new connection to the service, as the router does with root's.
    ///
    /// - Parameters:
    ///   - listener: The anonymous listener.
    ///   - connection: The new connection.
    /// - Returns: Always `true`.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        accepted.withLockUnchecked { $0.append(connection) }
        service.accept(connection)
        return true
    }
}


// MARK: - Reader
/// `macmonitor`'s ``StreamReaderProtocol`` in a test: it keeps every event and every saved mute set change, and
/// replies to each batch right away, or only when the test says so.
final class TestStreamReader: NSObject, StreamReaderProtocol {
    /// The events and changes received, and the replies held.
    private struct State {
        var events: [String] = []
        var changes: [MuteSetChange?] = []
        var held: [() -> Void] = []
        var holds = false
    }
    
    private let state = OSAllocatedUnfairLock(uncheckedState: State())
    
    /// Every event received, in order, as text.
    var events: [String] {
        state.withLockUnchecked { $0.events }
    }
    
    /// The saved mute set changes the stream was told about, in order: `nil` for one that didn't read.
    var changes: [MuteSetChange?] {
        state.withLockUnchecked { $0.changes }
    }
    
    /// How many batches await a reply.
    var heldCount: Int {
        state.withLockUnchecked { $0.held.count }
    }
    
    /// Hold the replies to batches from now on, as a `macmonitor` whose output is stalled does.
    func holdReplies() {
        state.withLockUnchecked { $0.holds = true }
    }
    
    /// Reply to every held batch, and stop holding.
    func releaseReplies() {
        let held = state.withLockUnchecked { state -> [() -> Void] in
            state.holds = false
            defer { state.held = [] }
            return state.held
        }
        held.forEach { $0() }
    }
    
    /// Keep the batch's events, then reply unless replies are held.
    ///
    /// - Parameters:
    ///   - events: The batch.
    ///   - reply: The batch's reply.
    func receive(events: [Data], reply: @escaping () -> Void) {
        let holding = state.withLockUnchecked { state -> Bool in
            state.events += events.map { String(decoding: $0, as: UTF8.self) }
            if state.holds { state.held.append(reply) }
            return state.holds
        }
        if !holding { reply() }
    }
    
    /// Keep a saved mute set change.
    ///
    /// - Parameter change: A JSON encoded ``MuteSetChange``.
    func savedMutesChanged(_ change: Data) {
        state.withLockUnchecked { $0.changes.append(MuteSetChange.decode(change)) }
    }
}


// MARK: - Requests
extension NSXPCConnection {
    /// Send a stream request and wait for the reply.
    ///
    /// - Parameters:
    ///   - request: The request's JSON.
    ///   - timeout: How long to wait.
    /// - Returns: The reply, or `nil` if none came.
    func send(_ request: Data, timeout: TimeInterval = 5) -> StreamReply? {
        let replied = DispatchSemaphore(value: 0)
        let reply = OSAllocatedUnfairLock<StreamReply?>(initialState: nil)
        sendAsync(request) { answer in
            reply.withLock { $0 = answer }
            replied.signal()
        }
        _ = replied.wait(timeout: .now() + timeout)
        return reply.withLock { $0 }
    }
    
    /// Send a stream request without waiting.
    ///
    /// - Parameters:
    ///   - request: The request's JSON.
    ///   - completion: Receives the reply, or `nil` if the message failed.
    func sendAsync(_ request: Data, completion: @escaping (StreamReply?) -> Void) {
        let proxy = remoteObjectProxyWithErrorHandler { _ in completion(nil) }
        (proxy as? StreamProtocol)?.perform(request) { completion(StreamReply.decode($0)) }
    }
    
    /// Send a mute request and wait for the reply.
    ///
    /// - Parameter request: The request.
    /// - Returns: The reply, or `nil` if none came.
    func sendMutes(_ request: MuteRequest) -> MuteReply? {
        let replied = DispatchSemaphore(value: 0)
        let reply = OSAllocatedUnfairLock<MuteReply?>(initialState: nil)
        let proxy = remoteObjectProxyWithErrorHandler { _ in replied.signal() }
        (proxy as? StreamProtocol)?.mutes(request.encoded()) { data in
            reply.withLock { $0 = MuteReply.decode(data) }
            replied.signal()
        }
        _ = replied.wait(timeout: .now() + 5)
        return reply.withLock { $0 }
    }
}
