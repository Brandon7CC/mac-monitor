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
/// The Security Extension's (sensor) side of the XPC connection.
///
/// Listens on `SensorXPC.machServiceName`, owns the Endpoint Security client through `EndpointSecurityManager`, and
/// streams batched events to the Mac Monitor connection that owns the event stream.
///
/// **Ownership:** the first connection to call `start(recording:reply:)` owns the event stream (the *sink*) until it goes
/// away. A second Mac Monitor (`open -n`, another user's session) gets `.tooManyClients` and can't change recording,
/// subscriptions, mutes, or install updates. It can still read state and check for updates. When the owner goes away we
/// post `SensorXPC.sensorReleasedNotification` so a refused Mac Monitor can claim the stream.
///
/// **Threading:** every piece of state below, and every call into `EndpointSecurityManager`, happens on `queue`. The
/// Endpoint Security handler only serializes events (while recording) and hops onto `queue` to buffer them.
///
/// **Lifecycle:** only the sink's connection going away deletes the ES client. Any other connection (e.g. an update
/// check that raced the handshake) can come and go without affecting monitoring.
final class SensorService: NSObject {
    // MARK: Tuning
    /// The most events sent in one XPC message.
    private static let batchSize: Int = 500
    /// How long a partial batch waits before it's sent.
    private static let flushDelay: DispatchTimeInterval = .milliseconds(100)
    /// The most batches awaiting Mac Monitor's reply. Past this we buffer instead of sending.
    private static let maxBatchesInFlight: Int = SensorXPC.maxBatchesInFlight
    /// The most events kept in memory while Mac Monitor catches up. Past this, new events spill to an ``EventSpool``
    /// file, so a stalled Mac Monitor can't grow a root process without bound. Nothing is dropped unless the spool is full
    /// too (``EventSpool/maxSize``, ``EventSpool/minFreeSpace``).
    private static let memoryBufferLimit: Int = 5_000
    
    private let esManager: EndpointSecurityManager
    private let updates = UpdateInstaller()
    private let listener = NSXPCListener(machServiceName: SensorXPC.machServiceName)
    private let queue = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.sensor")
    private let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "SensorService")
    
    /// The Mac Monitor connection receiving events, if any.
    private var sink: EventSink?
    
    /// - Parameter esManager: The Endpoint Security manager this service drives.
    init(esManager: EndpointSecurityManager) {
        self.esManager = esManager
        super.init()
    }
    
    /// Start accepting connections from Mac Monitor, then announce that we're ready.
    ///
    /// The code signing requirement is enforced by the listener, so a peer that doesn't satisfy
    /// `SensorXPC.agentRequirement` is rejected before ``listener(_:shouldAcceptNewConnection:)`` is consulted.
    ///
    /// Posting `SensorXPC.sensorReadyNotification` tells a running Mac Monitor to redo its handshake: after a crash,
    /// or after the extension was disabled and re-enabled, this process has no ES client until it does.
    func activate() {
        EventSpool.removeLeftovers()
        let declaredService = Bundle.main.object(forInfoDictionaryKey: "NSEndpointSecurityMachServiceName") as? String
        if declaredService != SensorXPC.machServiceName {
            logger.fault("NSEndpointSecurityMachServiceName (\(declaredService ?? "missing", privacy: .public)) does not match SensorXPC.machServiceName (\(SensorXPC.machServiceName, privacy: .public))!")
        }
        
        listener.setConnectionCodeSigningRequirement(SensorXPC.agentRequirement)
        listener.delegate = self
        listener.activate()
        logger.log("🔒 Listening for Mac Monitor on \(SensorXPC.machServiceName, privacy: .public)")
        notify_post(SensorXPC.sensorReadyNotification)
    }
    
    /// Run `work` on `queue` and reply with its result.
    ///
    /// - Parameters:
    ///   - reply: The XPC reply block.
    ///   - work: Produces the reply from the Endpoint Security manager.
    private func perform<Reply>(_ reply: @escaping (Reply) -> Void, _ work: @escaping (EndpointSecurityManager) -> Reply) {
        queue.async { [esManager] in
            reply(work(esManager))
        }
    }
    
    /// Like ``perform(_:_:)``, but only for the connection that owns the event stream. Any other connection gets
    /// `refused` and Endpoint Security is left untouched.
    ///
    /// - Parameters:
    ///   - refused: The reply for a connection that doesn't own the event stream.
    ///   - reply: The XPC reply block.
    ///   - work: Produces the reply from the Endpoint Security manager.
    private func performForOwner<Reply>(refusing refused: Reply, _ reply: @escaping (Reply) -> Void, _ work: @escaping (EndpointSecurityManager) -> Reply) {
        /// Must be read on the thread delivering the message, before hopping queues.
        let caller = NSXPCConnection.current()
        queue.async { [self] in
            reply(owns(caller) ? work(esManager) : refused)
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


// MARK: - Listener Delegate
extension SensorService: NSXPCListenerDelegate {
    /// Configure and accept a connection that has already passed `SensorXPC.agentRequirement`.
    ///
    /// - Parameters:
    ///   - listener: Our Mach service listener.
    ///   - connection: The incoming Mac Monitor connection.
    /// - Returns: Always `true`. Peers that fail the code signing requirement never reach the delegate.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = SensorXPC.sensorInterface
        connection.exportedObject = self
        connection.remoteObjectInterface = SensorXPC.agentInterface
        
        connection.invalidationHandler = { [weak self, weak connection] in
            guard let self, let connection else { return }
            self.queue.async { self.detach(connection) }
        }
        
        connection.activate()
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
                return reply(.tooManyClients)
            }
            if sink == nil { sink = EventSink(connection: caller) }
            
            let result = esManager.kickstartClient { [weak self] event in
                self?.queue.async { self?.enqueue(event) }
            }
            esManager.isRecording = recording
            logger.log("Mac Monitor connected (recording: \(recording)). ES client result: \(result.rawValue)")
            reply(result)
        }
    }
    
    func setRecording(_ enabled: Bool, reply: @escaping (Bool) -> Void) {
        performForOwner(refusing: false, reply) { esManager in
            esManager.isRecording = enabled
            return esManager.esClient != nil
        }
    }
    
    func eventSubscriptions(reply: @escaping ([String]) -> Void) {
        perform(reply) { $0.seGetEventSubscriptionsAsString().sorted() }
    }
    
    func setSubscription(_ event: String, enabled: Bool, reply: @escaping (Bool) -> Void) {
        performForOwner(refusing: false, reply) { $0.setEventSubscription(event, enabled: enabled) }
    }
    
    func mutedPaths(reply: @escaping ([String]) -> Void) {
        perform(reply) { $0.seGetGlobalMutedPaths().sorted() }
    }
    
    func appleMuteSet(reply: @escaping ([String]) -> Void) {
        perform(reply) { $0.seGetAppleMuteSet().sorted() }
    }
    
    func setMute(_ path: String, type: String, events: [String], muted: Bool, reply: @escaping (Bool) -> Void) {
        performForOwner(refusing: false, reply) { $0.setPathMute(path, type: getMuteCaseFromString(muteString: type), events: events, muted: muted) }
    }
    
    func resetMutes(reply: @escaping (Bool) -> Void) {
        performForOwner(refusing: false, reply) { esManager in
            guard let esClient = esManager.esClient else { return false }
            MutingEngine.applyDefaultMuteSet(client: esClient)
            return true
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
            /// `--deactive-security-extension`). While someone does, only they may.
            guard sink == nil || owns(caller) else { return reply(false) }
            updates.install(reply: reply)
        }
    }
}


// MARK: - Event streaming
extension SensorService {
    /// Tear down monitoring if `connection` was the event sink.
    ///
    /// - Parameter connection: A connection that was just invalidated.
    private func detach(_ connection: NSXPCConnection) {
        guard let current = sink, current.connection === connection else { return }
        logger.log("Mac Monitor disconnected after \(current.deliveredEvents) of \(current.enqueuedEvents) events (\(current.spooledEvents) went through the spool). Deleting the Endpoint Security client.")
        reportDrops(of: current)
        sink = nil
        esManager.cleanup()
        /// Let a Mac Monitor that was refused with `.tooManyClients` claim the stream.
        notify_post(SensorXPC.sensorReleasedNotification)
    }
    
    /// Buffer one serialized event and send it when a batch fills up or `flushDelay` elapses.
    ///
    /// Events stay in memory until `memoryBufferLimit`, then spill to the sink's ``EventSpool``. Once anything is spooled,
    /// newer events go to the spool too until it drains, so Mac Monitor always receives events in order.
    ///
    /// - Parameter event: A JSON serialization of `Message`.
    private func enqueue(_ event: Data) {
        guard let sink else { return }
        sink.enqueuedEvents += 1
        if sink.spool == nil && sink.buffer.count < Self.memoryBufferLimit {
            sink.buffer.append(event)
        } else {
            spill(event, to: sink)
        }
        
        if sink.buffer.count >= Self.batchSize {
            flush(sink)
        } else if !sink.isFlushScheduled {
            sink.isFlushScheduled = true
            queue.asyncAfter(deadline: .now() + Self.flushDelay) { [weak self, weak sink] in
                guard let self, let sink else { return }
                sink.isFlushScheduled = false
                self.flush(sink)
            }
        }
    }
    
    /// Send the next batch unless too many are already awaiting Mac Monitor's reply.
    ///
    /// Each reply calls back in here, so a backlog drains as fast as Mac Monitor takes it. A failed delivery only frees
    /// its slot: on a listener connection that means Mac Monitor is gone, and ``detach(_:)`` is about to run.
    ///
    /// - Parameter sink: The sink to flush. Ignored if it's no longer the current sink.
    private func flush(_ sink: EventSink) {
        guard sink === self.sink else { return }
        refill(sink)
        guard !sink.buffer.isEmpty, sink.batchesInFlight < Self.maxBatchesInFlight else { return }
        
        let batchCount: Int = min(sink.buffer.count, Self.batchSize)
        let finished: (_ delivered: Bool) -> Void = { [weak self, weak sink] delivered in
            self?.queue.async {
                guard let self, let sink else { return }
                sink.batchesInFlight -= 1
                guard delivered else { return }
                sink.deliveredEvents += batchCount
                self.flush(sink)
            }
        }
        let proxy = sink.connection.remoteObjectProxyWithErrorHandler { [logger] error in
            logger.error("Failed to deliver \(batchCount) events to Mac Monitor: \(error.localizedDescription, privacy: .public)")
            finished(false)
        }
        guard let agent = proxy as? AgentProtocol else {
            logger.fault("The remote object proxy does not conform to AgentProtocol!")
            return
        }
        
        let batch = Array(sink.buffer.prefix(batchCount))
        sink.buffer.removeFirst(batchCount)
        sink.batchesInFlight += 1
        reportDrops(of: sink)
        agent.receive(events: batch) { finished(true) }
    }
    
    /// Append an event to the sink's spool file, creating the spool on first use.
    ///
    /// - Parameters:
    ///   - event: A JSON serialization of `Message`.
    ///   - sink: The sink that's behind.
    private func spill(_ event: Data, to sink: EventSink) {
        do {
            if sink.spool == nil {
                sink.spool = try EventSpool()
                logger.log("Mac Monitor is \(sink.buffer.count) events behind. Spooling new events to disk.")
            }
            try sink.spool?.append(event)
            sink.spooledEvents += 1
        } catch {
            /// Only a full spool, or a disk that refuses the write, loses events. Reported from ``flush(_:)``.
            sink.droppedEvents += 1
        }
    }
    
    /// Move spooled events back into memory, oldest first, as room frees up. Releases the spool once it's drained.
    ///
    /// - Parameter sink: The sink to refill.
    private func refill(_ sink: EventSink) {
        guard let spool = sink.spool, sink.buffer.count < Self.memoryBufferLimit else { return }
        do {
            sink.buffer.append(contentsOf: try spool.read(upTo: Self.memoryBufferLimit - sink.buffer.count))
        } catch {
            logger.fault("The event spool is unreadable. \(spool.count) spooled events are lost: \(error.localizedDescription, privacy: .public)")
            sink.spool = nil
            return
        }
        if spool.count == 0 {
            sink.spool = nil
            logger.log("Mac Monitor caught up. The event spool is drained.")
        }
    }
    
    /// Log how many events the spool couldn't take since the last report.
    ///
    /// - Parameter sink: The sink whose drop counter to report and reset.
    private func reportDrops(of sink: EventSink) {
        guard sink.droppedEvents > 0 else { return }
        logger.fault("Dropped \(sink.droppedEvents) events: the event spool is full or couldn't be written.")
        sink.droppedEvents = 0
    }
}


// MARK: - Event sink
/// The Mac Monitor connection that receives events, plus the events waiting to be sent to it: the oldest in memory, any
/// overflow in a spool file. Only touched on `SensorService`'s queue.
private final class EventSink {
    let connection: NSXPCConnection
    /// Events waiting in memory, oldest first.
    var buffer: [Data] = []
    /// Overflow on disk. Every event in it is newer than every event in `buffer`.
    var spool: EventSpool?
    var batchesInFlight: Int = 0
    /// Lifetime counters, logged when the sink goes away.
    var enqueuedEvents: Int = 0, spooledEvents: Int = 0, deliveredEvents: Int = 0
    /// Events the spool couldn't take since the last report.
    var droppedEvents: Int = 0
    var isFlushScheduled: Bool = false
    
    /// - Parameter connection: The connection that called `start(recording:reply:)`.
    init(connection: NSXPCConnection) {
        self.connection = connection
    }
}
