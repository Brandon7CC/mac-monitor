//
//  CaptureSession.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity
import OSLog


// MARK: - Capture session
/// Endpoint Security capture split across one client per ``EventClass``: what the Security Extension runs for Mac
/// Monitor, and what it can run for each `macmonitor` stream.
///
/// **Clients:** each client subscribes only to its class's share of the events (``EventClassTable``). Endpoint
/// Security hands each client its messages serially on the client's own queue, so the classes are handled in parallel
/// and a flood of file events no longer holds up process events. There's no worker pool: each event is built and
/// encoded in its client's handler.
///
/// **Mutes:** every client mutes this process and has the same path mutes: Mac Monitor's default set, the
/// configuration's, and every later ``setPathMute(_:muted:)`` and ``apply(_:)``. They're in place before the first
/// subscription, so no message arrives unmuted.
///
/// **Order:** each class's events are emitted in the order its client delivers them, so `fork`, `exec`, and `exit`
/// keep Endpoint Security's order. Classes interleave in the order their events are handled; nothing re-sorts them by
/// `mach_time`.
///
/// **Threading:** not thread-safe. Create the session and call it on one serial queue. Only the clients' handlers run
/// elsewhere, and they call `emit`, which must not block or call back into the session.
public final class CaptureSession {
    /// The Endpoint Security clients each session holds, which count against the system's limit.
    public static let clientsPerSession: Int = EventClass.allCases.count
    /// Names the session in the log.
    public let label: String
    /// The subscribed events, in the order they were subscribed.
    public private(set) var subscribedEvents: [es_event_type_t]
    /// Endpoint Security's own default mutes (``ESMutedPath`` JSON), read before any of Mac Monitor's were applied.
    public let appleMuteSet: Set<String>
    /// Serialize and emit events? A new session isn't recording. Setting it never waits for an event being built.
    public var isRecording: Bool = false {
        didSet { lanes.forEach { $0.setRecording(isRecording) } }
    }
    /// One lane per class, in ``EventClass/allCases`` order.
    let lanes: [CaptureLane]
    /// Computes the Sensor ID stamped on events.
    private let makeSensorID: () -> String
    private var isStopped: Bool = false
    /// How long stopping waits for the events being built, unless a test sets ``closeTimeout``.
    static let defaultCloseTimeout: DispatchTimeInterval = .seconds(1)
    /// How long ``stop()`` waits for an event being built before it leaves that client to be deleted once it's done.
    var closeTimeout = CaptureSession.defaultCloseTimeout
    /// When drops were last reported (uptime nanoseconds), for ``reportDrops(now:)``.
    var lastDropReport: UInt64?
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "CaptureSession")
    
    /// Create, mute, and subscribe one live Endpoint Security client per class. Not recording until ``isRecording``
    /// is set.
    ///
    /// - Parameters:
    ///   - configuration: The events to subscribe to, and the mutes.
    ///   - emit: Receives each event, on its client's handler queue. It must not block or call back into the session.
    /// - Throws: ``CaptureStartError``, once every client already created is deleted.
    public convenience init(_ configuration: CaptureConfiguration,
                            emit: @escaping (CapturedEvent) -> Void) throws {
        try self.init(configuration, clients: LiveEndpointSecurityClientFactory(), serializer: MessageSerializer(),
                      sensorID: EndpointSecurityManager.makeSensorID, emit: emit)
    }
    
    /// Create, mute, and subscribe one client per class. Not recording until ``isRecording`` is set.
    ///
    /// 1. Create every client before configuring any. A client gets no messages until it subscribes, so if one is
    ///    refused (usually because the system has too many clients) the others are simply deleted.
    /// 2. Read Endpoint Security's default mutes from the first client.
    /// 3. Mute this process and every path on each client, then subscribe each to its class's events.
    ///
    /// - Parameters:
    ///   - configuration: The events to subscribe to, and the mutes.
    ///   - factory: Makes the clients.
    ///   - serializer: Builds each event's JSON.
    ///   - makeSensorID: Computes the Sensor ID stamped on events, now and on ``refreshSensorID()``.
    ///   - emit: Receives each event, on its client's handler queue. It must not block or call back into the session.
    /// - Throws: ``CaptureStartError``, once every client already created is deleted.
    init(_ configuration: CaptureConfiguration, clients factory: any EndpointSecurityClientFactory,
         serializer: any EventSerializing, sensorID makeSensorID: @escaping () -> String,
         emit: @escaping (CapturedEvent) -> Void) throws {
        let label = configuration.label
        let events = Self.capturable(configuration.events, label: label)
        let sensorID = makeSensorID()
        let lanes = EventClass.allCases.map { CaptureLane($0, sensorID: sensorID, serializer: serializer, emit: emit) }
        try Self.createClients(for: lanes, with: factory, label: label)
        appleMuteSet = Set((lanes.first?.client?.mutedPaths() ?? []).map { pathToJSON(value: $0) })
        Self.applyMutes(of: configuration, to: lanes)
        try Self.subscribe(lanes, to: events, label: label)
        
        self.label = label
        self.lanes = lanes
        self.makeSensorID = makeSensorID
        subscribedEvents = events
        let shares = lanes.map { lane in "\(lane.eventClass.rawValue) \(events.filter(lane.serves).count)" }
        Self.logger.log("""
            \(label, privacy: .public): capturing with \(lanes.count) Endpoint Security clients \
            (events: \(shares.joined(separator: ", "), privacy: .public)).
            """)
    }
    
    deinit {
        stop()
    }
    
    /// Recompute the Sensor ID, which follows the console user, and stamp it on events from now on. Never waits for an
    /// event being built.
    public func refreshSensorID() {
        let sensorID = makeSensorID()
        lanes.forEach { $0.setSensorID(sensorID) }
    }
    
    /// Subscribe to, or unsubscribe from, one event on the client of its class.
    ///
    /// - Parameters:
    ///   - event: A NOTIFY event Mac Monitor models.
    ///   - enabled: `true` to subscribe, `false` to unsubscribe.
    /// - Returns: `true` if Endpoint Security accepted the request. `false` after ``stop()``, or for an event Mac
    ///   Monitor doesn't model (an AUTH event, or an unknown name read as `ES_EVENT_TYPE_LAST`).
    @discardableResult
    public func setSubscription(_ event: es_event_type_t, enabled: Bool) -> Bool {
        guard !isStopped, Self.isCapturable(event),
              let client = lanes.first(where: { $0.serves(event) })?.client else { return false }
        guard enabled ? client.subscribe([event]) : client.unsubscribe([event]) else {
            Self.logger.error("""
                \(self.label, privacy: .public): Endpoint Security refused to \
                \(enabled ? "subscribe to" : "unsubscribe from", privacy: .public) \
                \(eventTypeToString(from: event), privacy: .public).
                """)
            return false
        }
        if !enabled {
            subscribedEvents.removeAll { $0 == event }
        } else if !subscribedEvents.contains(event) {
            subscribedEvents.append(event)
        }
        return true
    }
    
    /// Mute or unmute a path on every client, so it applies whichever client serves an event.
    ///
    /// - Parameters:
    ///   - mute: The path, its type, and the events it's scoped to.
    ///   - muted: `true` to mute, `false` to unmute.
    /// - Returns: `true` if every client accepted it. A refusal is logged, and the other clients keep the change.
    @discardableResult
    public func setPathMute(_ mute: PathMute, muted: Bool) -> Bool {
        guard !isStopped else { return false }
        return Self.setPathMutes([mute], muted: muted, on: lanes, label: label)
    }
    
    /// Mute every path of a mute set on every client. Mutes already in place, such as the user's, stay.
    ///
    /// - Parameter muteSet: The mute set, such as ``MuteSet/default``.
    /// - Returns: `true` if every client accepted every mute. Refusals are logged, and the rest still apply.
    @discardableResult
    public func apply(_ muteSet: MuteSet) -> Bool {
        guard !isStopped else { return false }
        return Self.setPathMutes(muteSet.pathMutes, muted: true, on: lanes, label: label)
    }
    
    /// Every muted path, over all the clients. Their mutes are the same unless a client refused one.
    ///
    /// - Returns: JSON serializations of ``ESMutedPath``. Empty after ``stop()``.
    public func mutedPaths() -> Set<String> {
        guard !isStopped else { return [] }
        return Set(lanes.flatMap { $0.client?.mutedPaths() ?? [] }.map { pathToJSON(value: $0) })
    }
    
    /// Stop capturing and delete every client. Calling it again does nothing.
    ///
    /// 1. `es_unsubscribe_all` on each client: Endpoint Security stops generating messages for it.
    /// 2. Close every lane: messages still on their way are counted and ignored, as they are when recording stops.
    /// 3. Wait up to ``closeTimeout`` for the events being built. A lane that's done calls Endpoint Security and emits
    ///    no more, and `es_delete_client` deletes its client. `ESClient.h` forbids overlapping that with any other call
    ///    on the client, and nothing can make one: this queue makes every other call.
    /// 4. A lane still building an event at the deadline (a script read from a slow disk, a signature `trustd` is slow
    ///    to check) drops it, and its client is deleted on a background queue once the event is done. So a slow event
    ///    never holds up this queue, and nothing is emitted once this returns.
    public func stop() {
        guard !isStopped else { return }
        isStopped = true
        Self.tearDown(lanes, label: label, timeout: closeTimeout)
        Self.logger.log("\(self.label, privacy: .public): stopped capturing and deleted its Endpoint Security clients.")
        logStatistics()
    }
}


// MARK: - Starting and stopping
extension CaptureSession {
    /// The events a session can subscribe to, each once, in their order: the NOTIFY events Mac Monitor models.
    ///
    /// - Parameters:
    ///   - events: The requested events.
    ///   - label: Names the session in the log, which lists the events left out.
    /// - Returns: The events that are kept.
    static func capturable(_ events: [es_event_type_t], label: String) -> [es_event_type_t] {
        var seen = Set<UInt32>()
        let kept = events.filter { isCapturable($0) && seen.insert($0.rawValue).inserted }
        let leftOut = events.filter { !isCapturable($0) }.map { eventTypeToString(from: $0) }
        if !leftOut.isEmpty {
            logger.error("""
                \(label, privacy: .public): not subscribing to events Mac Monitor doesn't model: \
                \(leftOut.joined(separator: ", "), privacy: .public).
                """)
        }
        return kept
    }
    
    /// Can a session subscribe to an event?
    ///
    /// - Parameter event: An event type.
    /// - Returns: `true` for a NOTIFY event Mac Monitor models (`supportedEvents`).
    static func isCapturable(_ event: es_event_type_t) -> Bool {
        supportedEvents.contains(event)
    }
    
    /// Create a client for each lane, all or nothing.
    ///
    /// - Parameters:
    ///   - lanes: The lanes, each given its client.
    ///   - factory: Makes the clients.
    ///   - label: Names the session in the log.
    /// - Throws: ``CaptureStartError/clientRefused(_:_:)``, once every client already created is deleted. None has
    ///   subscribed yet, so none has had a message.
    private static func createClients(for lanes: [CaptureLane], with factory: any EndpointSecurityClientFactory,
                                      label: String) throws {
        for lane in lanes {
            do {
                lane.attach(try factory.makeClient(handler: lane.handle))
            } catch {
                let result = (error as? ClientRefusal)?.result ?? .internalSubsystem
                lanes.forEach { $0.deleteClient() }
                logger.error("""
                    \(label, privacy: .public): Endpoint Security refused the \
                    \(lane.eventClass.rawValue, privacy: .public) client (result \(result.rawValue)). \
                    Deleted the clients already created.
                    """)
                throw CaptureStartError.clientRefused(lane.eventClass, result)
            }
        }
    }
    
    /// Mute this process and the configuration's paths on every lane's client.
    ///
    /// A refusal is logged and the rest still apply, as Mac Monitor's mutes always have been.
    ///
    /// - Parameters:
    ///   - configuration: Which mutes to apply.
    ///   - lanes: The lanes, each with its client.
    private static func applyMutes(of configuration: CaptureConfiguration, to lanes: [CaptureLane]) {
        if configuration.mutesSelf {
            let token = audit_token_t.currentProcess
            for lane in lanes where lane.client?.muteProcess(token) != true {
                logger.fault("""
                    \(configuration.label, privacy: .public): couldn't mute this process on the \
                    \(lane.eventClass.rawValue, privacy: .public) client, so its own activity will be captured.
                    """)
            }
        }
        let mutes = (configuration.appliesDefaultMuteSet ? MuteSet.default.pathMutes : []) + configuration.mutes
        setPathMutes(mutes, muted: true, on: lanes, label: configuration.label)
    }
    
    /// Mute or unmute paths on every lane's client.
    ///
    /// - Parameters:
    ///   - mutes: The mutes.
    ///   - muted: `true` to mute, `false` to unmute.
    ///   - lanes: The lanes.
    ///   - label: Names the session in the log, which counts each client's refusals.
    /// - Returns: `true` if every client accepted every request.
    @discardableResult
    private static func setPathMutes(_ mutes: [PathMute], muted: Bool, on lanes: [CaptureLane], label: String) -> Bool {
        var accepted = true
        for lane in lanes {
            let refused = mutes.filter { lane.client?.setPathMute($0, muted: muted) != true }
            guard !refused.isEmpty else { continue }
            accepted = false
            logger.error("""
                \(label, privacy: .public): the \(lane.eventClass.rawValue, privacy: .public) client refused \
                \(refused.count) of \(mutes.count) path \(muted ? "mutes" : "unmutes", privacy: .public), \
                such as \(refused[0].path).
                """)
        }
        return accepted
    }
    
    /// Subscribe each lane's client to its class's share of the events, all or nothing.
    ///
    /// - Parameters:
    ///   - lanes: The lanes, each with its client.
    ///   - events: Every event to subscribe to.
    ///   - label: Names the session in the log.
    /// - Throws: ``CaptureStartError/subscriptionFailed(_:)``, once every client is torn down.
    private static func subscribe(_ lanes: [CaptureLane], to events: [es_event_type_t], label: String) throws {
        let split = EventClassTable.split(events)
        for lane in lanes where lane.client?.subscribe(split[lane.eventClass] ?? []) != true {
            tearDown(lanes, label: label, timeout: defaultCloseTimeout)
            logger.error("""
                \(label, privacy: .public): the \(lane.eventClass.rawValue, privacy: .public) client couldn't \
                subscribe to its events. Deleted every client.
                """)
            throw CaptureStartError.subscriptionFailed(lane.eventClass)
        }
    }
    
    /// Unsubscribe every client, close every lane, then delete every client (see ``stop()``).
    ///
    /// - Parameters:
    ///   - lanes: The lanes.
    ///   - label: Names the session in the log.
    ///   - timeout: How long to wait for the events being built.
    private static func tearDown(_ lanes: [CaptureLane], label: String, timeout: DispatchTimeInterval) {
        lanes.forEach { _ = $0.client?.unsubscribeAll() }
        lanes.forEach { $0.close() }
        let deadline = DispatchTime.now() + timeout
        for lane in lanes {
            let eventClass = lane.eventClass
            guard lane.waitUntilIdle(until: deadline) else {
                logger.fault("""
                    \(label, privacy: .public): the \(eventClass.rawValue, privacy: .public) client was still building \
                    an event at the deadline. Dropped the event; the client is deleted once it's done.
                    """)
                lane.deleteClientOnceIdle { logDeletion(freed: $0, of: eventClass, label: label) }
                continue
            }
            logDeletion(freed: lane.deleteClient(), of: eventClass, label: label)
        }
    }
    
    /// Log a client whose deletion leaked Endpoint Security's resources.
    ///
    /// - Parameters:
    ///   - freed: Whether Endpoint Security freed the client's resources.
    ///   - eventClass: The client's class.
    ///   - label: Names the session in the log.
    private static func logDeletion(freed: Bool, of eventClass: EventClass, label: String) {
        guard !freed else { return }
        logger.error("""
            \(label, privacy: .public): Endpoint Security leaked the \(eventClass.rawValue, privacy: .public) client's \
            resources while deleting it.
            """)
    }
}
