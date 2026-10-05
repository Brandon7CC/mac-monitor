//
//  SensorService.swift
//  SecurityExtension
//
//  Created by Brandon Dalton on 10/1/26.
//

import Foundation
import EndpointSecurity
import OSLog
import notify
import SutroESFramework


// MARK: - Sensor service
/// The Security Extension's (sensor) side of Mac Monitor's XPC connections.
///
/// ``SensorListener`` hands it every connection that isn't root's. It runs capture with a `CaptureSession` (one
/// Endpoint Security client per event class), and streams batched events to the Mac Monitor connection that owns the
/// event stream.
///
/// **Ownership:** the first connection to call `start(recording:reply:)` and get capture running owns the event stream
/// (the *sink*) until it goes away. A second Mac Monitor (`open -n`, another user's session) gets `.streamOwned` and
/// can't change recording, subscriptions, the saved mute set, or install updates. It can still read state and check
/// for updates. A start Endpoint Security refuses (`.tooManyClients` while `macmonitor` streams hold clients, say)
/// leaves no owner. When the owner goes away we post `SensorXPC.sensorReleasedNotification` so a refused Mac Monitor
/// can claim the stream; `StreamService` posts it too when a stream frees its clients.
///
/// **Saved mute set:** only an administrator's Mac Monitor may change it (`AdministratorCheck`, asked on every
/// request), and only while it owns the event stream or nobody does. A standard user's Mac Monitor still lists it,
/// exports it, and records with it.
///
/// **Threading:** every piece of state below, and every call into the `CaptureSession`, happens on `queue`. The
/// Endpoint Security handlers only serialize events (while recording) and hop onto `queue` to buffer them, so each
/// class's events reach Mac Monitor in its client's order.
///
/// **Lifecycle:** only the sink's connection going away stops capture and deletes the ES clients. Any other connection
/// (e.g. an update check that raced the handshake) can come and go without affecting monitoring.
final class SensorService: NSObject {
    /// The Mac Monitor connection that owns the event stream, and the batcher sending events to it.
    private struct Sink {
        /// The connection that called `start(recording:reply:)`.
        let connection: NSXPCConnection
        /// Sends events to `connection`. Closed when it goes away.
        let batcher: EventBatcher
    }
    
    private let updates = UpdateInstaller()
    private let queue = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.sensor")
    private let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "SensorService")
    
    /// The Mac Monitor connection receiving events, and the batcher sending them, if any.
    private var sink: Sink?
    
    /// Capture for the sink, while there is one.
    private var capture: CaptureSession?
    
    /// Mac Monitor's event subscriptions. They outlive a capture session, so a Mac Monitor that reconnects keeps the
    /// ones it chose.
    private var subscriptions: [es_event_type_t] = defaultEventSubscriptions
    
    /// Endpoint Security's default mutes (``ESMutedPath`` JSON), from the first capture session this process started.
    private var appleDefaultMutes: Set<String> = []
    
    /// The saved mute set, shared with every `macmonitor` stream. Capture follows it while `muteSubscription` is held:
    /// each change is saved, then applied.
    private let savedMutes: SavedMuteSet
    private var muteSubscription: MuteSubscription?
    /// Decides whose Mac Monitor may change the saved mute set: an administrator's.
    private let administrators: AdministratorCheck
    
    /// - Parameters:
    ///   - savedMutes: The saved mute set, loaded before the listener starts.
    ///   - administrators: Decides whose Mac Monitor may change it.
    init(savedMutes: SavedMuteSet, administrators: AdministratorCheck = .openDirectory) {
        self.savedMutes = savedMutes
        self.administrators = administrators
    }
    
    /// Configure and activate a Mac Monitor connection the router pinned to `SensorXPC.agentRequirement`.
    ///
    /// - Parameter connection: The incoming Mac Monitor connection, not yet activated.
    func accept(_ connection: NSXPCConnection) {
        connection.exportedInterface = SensorXPC.sensorInterface
        connection.exportedObject = self
        connection.remoteObjectInterface = SensorXPC.agentInterface
        
        connection.invalidationHandler = { [weak self, weak connection] in
            guard let self, let connection else { return }
            self.queue.async { self.detach(connection) }
        }
        
        connection.activate()
    }
    
    /// Run `work` on `queue` and reply with its result.
    ///
    /// - Parameters:
    ///   - reply: The XPC reply block.
    ///   - work: Produces the reply.
    private func perform<Reply>(_ reply: @escaping (Reply) -> Void, _ work: @escaping () -> Reply) {
        queue.async {
            reply(work())
        }
    }
    
    /// Like ``perform(_:_:)``, but only for the connection that owns the event stream. Any other connection gets
    /// `refused` and Endpoint Security is left untouched.
    ///
    /// - Parameters:
    ///   - refused: The reply for a connection that doesn't own the event stream.
    ///   - reply: The XPC reply block.
    ///   - work: Produces the reply.
    private func performForOwner<Reply>(refusing refused: Reply, _ reply: @escaping (Reply) -> Void,
                                        _ work: @escaping () -> Reply) {
        /// Must be read on the thread delivering the message, before hopping queues.
        let caller = NSXPCConnection.current()
        queue.async { [self] in
            reply(owns(caller) ? work() : refused)
        }
    }
    
    /// Does `caller` own the event stream? Call on `queue`.
    ///
    /// - Parameter caller: The connection a request arrived on.
    /// - Returns: `true` if `caller` is the sink's connection. Otherwise logs the refusal and returns `false`.
    private func owns(_ caller: NSXPCConnection?) -> Bool {
        guard let caller, caller === sink?.connection else {
            logger.error("Refusing a control request from a Mac Monitor connection that doesn't own the event stream.")
            return false
        }
        return true
    }
}


// MARK: - SensorProtocol
extension SensorService: SensorProtocol {
    func start(recording: Bool, reply: @escaping (NewClientResult) -> Void) {
        /// Must be read on the thread delivering the message, before hopping queues.
        guard let caller = NSXPCConnection.current() else {
            logger.fault("start(recording:reply:) was called outside of an XPC message!")
            return reply(.internalSubsystem)
        }
        
        queue.async { [self] in
            if let owner = sink, owner.connection !== caller {
                logger.error("Refusing start from a second Mac Monitor connection (pid \(caller.processIdentifier)). A connection from pid \(owner.connection.processIdentifier) owns the event stream.")
                return reply(.streamOwned)
            }
            let claims = sink == nil
            if claims { sink = Sink(connection: caller, batcher: makeBatcher(for: caller)) }
            
            let result = startCapture()
            /// A handshake Endpoint Security refused never leaves an owner without capture.
            if result != .success, claims {
                sink?.batcher.close()
                sink = nil
            }
            capture?.isRecording = recording
            logger.log("Mac Monitor connected (recording: \(recording)). Endpoint Security result: \(result.rawValue)")
            reply(result)
        }
    }
    
    func setRecording(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        performForOwner(refusing: false, reply) { [self] in
            capture?.isRecording = enabled
            return capture != nil
        }
    }
    
    func eventSubscriptions(reply: @escaping ([String]) -> Void) {
        perform(reply) { [self] in
            Set((capture?.subscribedEvents ?? subscriptions).map { eventTypeToString(from: $0) }).sorted()
        }
    }
    
    func setSubscription(_ event: String, enabled: Bool, reply: @escaping (Bool) -> Void) {
        performForOwner(refusing: false, reply) { [self] in
            guard let capture, capture.setSubscription(eventStringToType(from: event), enabled: enabled) else {
                return false
            }
            subscriptions = capture.subscribedEvents
            return true
        }
    }
    
    func appleMuteSet(reply: @escaping ([String]) -> Void) {
        perform(reply) { [self] in appleDefaultMutes.sorted() }
    }
    
    func mutes(_ request: Data, reply: @escaping (Data) -> Void) {
        /// Must be read on the thread delivering the message, before hopping queues. Open Directory answers here, on
        /// the connection's own queue, so a slow lookup never holds up `queue`, which buffers events. No connection
        /// means no user to vouch for, so nothing may change.
        let caller = NSXPCConnection.current()
        let isAdministrator = administrators.isAdministrator(caller)
        queue.async { [self] in
            /// Only an administrator's Mac Monitor may change the saved set. Like `installUpdate`, it may while nobody
            /// owns the event stream, and while someone does, only they may. Every Mac Monitor may list it.
            let access = MuteAccess.app(isAdministrator: isAdministrator,
                                        controlsStream: sink == nil || caller === sink?.connection)
            savedMutes.handle(request, access: access, caller: "Mac Monitor (pid \(caller?.processIdentifier ?? 0))",
                              reply: reply)
        }
    }
    
    // Network work runs on UpdateInstaller's own tasks so it never blocks `queue`.
    func checkForUpdate(reply: @escaping (Data?) -> Void) {
        updates.check(reply: reply)
    }
    
    func installUpdate(reply: @escaping (Bool) -> Void) {
        let caller = NSXPCConnection.current()
        queue.async { [self] in
            /// Any Mac Monitor may install while nobody owns the stream (e.g. one launched with
            /// `--deactivate-security-extension`). While someone does, only they may.
            guard sink == nil || owns(caller) else { return reply(false) }
            updates.install(reply: reply)
        }
    }
}


// MARK: - Event streaming
extension SensorService {
    /// Start capture if there's no session yet, else refresh its Sensor ID (which follows the console user). Call on
    /// `queue`.
    ///
    /// - Returns: `.success`, or why Endpoint Security refused, such as `.tooManyClients`.
    private func startCapture() -> NewClientResult {
        if let capture {
            capture.refreshSensorID()
            return .success
        }
        /// Follow the saved set from the moment it's read, so no change is missed. Changes hop onto `queue`.
        let (mutes, subscription) = savedMutes.follow { [weak self] list, _ in
            self?.queue.async { self?.capture?.applyMutes(list) }
        }
        do {
            var configuration = CaptureConfiguration(events: subscriptions, label: "Mac Monitor")
            configuration.mutes = mutes
            let session = try CaptureSession(configuration) { [weak self] event in
                self?.queue.async { self?.sink?.batcher.enqueue(event.json) }
            }
            if appleDefaultMutes.isEmpty { appleDefaultMutes = session.appleMuteSet }
            capture = session
            muteSubscription = subscription
            return .success
        } catch {
            return (error as? CaptureStartError)?.clientResult ?? .internalSubsystem
        }
    }
    
    /// Tear down monitoring if `connection` was the event sink.
    ///
    /// - Parameter connection: A connection that was just invalidated.
    private func detach(_ connection: NSXPCConnection) {
        guard let current = sink, current.connection === connection else { return }
        let counters = current.batcher.counters
        logger.log("""
            Mac Monitor disconnected after \(counters.delivered) of \(counters.enqueued) events \
            (\(counters.spooled) went through the spool). Stopping capture.
            """)
        current.batcher.close()
        sink = nil
        capture?.stop()
        capture = nil
        muteSubscription = nil
        /// Let a Mac Monitor that was refused (`.streamOwned`, `.tooManyClients`) claim the stream.
        notify_post(SensorXPC.sensorReleasedNotification)
    }
    
    /// Batch events for Mac Monitor: in memory up to ``EventBatcher/Limits-swift.struct/app``'s limit, then spilled to
    /// an ``EventSpool`` file, so a stalled Mac Monitor can't grow a root process without bound. Nothing is dropped
    /// unless the spool is full too (``EventSpool/maxSize``, ``EventSpool/minFreeSpace``).
    ///
    /// - Parameter connection: The connection that claimed the event stream.
    /// - Returns: The batcher. Each batch sent also logs what Endpoint Security dropped since the last report.
    private func makeBatcher(for connection: NSXPCConnection) -> EventBatcher {
        EventBatcher(queue: queue, limits: .app, overflow: .backlog { try EventSpool() },
                     delivery: XPCBatchDelivery(connection: connection, label: "Mac Monitor"),
                     willSend: { [weak self] in self?.capture?.reportDrops() }, label: "Mac Monitor")
    }
}
