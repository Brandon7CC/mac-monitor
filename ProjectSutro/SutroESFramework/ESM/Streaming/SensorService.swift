//
//  SensorService.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/1/26.
//

import Foundation
import Combine
import EndpointSecurity
import OSLog
import notify


// MARK: - Updates
/// Checks for and installs Mac Monitor's releases for the ``SensorService`` (Security Extension context). The
/// Security Extension's installer resolves, downloads and verifies a release itself (``ReleaseChoice``,
/// ``UpdateVerdict``).
public protocol SensorUpdating: AnyObject {
    /// Check for a newer release.
    ///
    /// - Parameter reply: A JSON encoded ``UpdateCheck``, or `nil` when this build doesn't update itself.
    func check(reply: @escaping (Data?) -> Void)

    /// Download, verify, and install the latest release.
    ///
    /// - Parameters:
    ///   - progress: Called as each step starts, and as the download goes.
    ///   - reply: `nil` if the update was installed, else why not.
    func install(progress: @escaping (UpdateProgress) -> Void, reply: @escaping (UpdateFailure?) -> Void)
}


// MARK: - Sensor service
/// The Security Extension's (sensor) side of Mac Monitor's XPC connections.
///
/// The Security Extension's listener hands it every connection that isn't root's or signed as `macmonitor`. It runs
/// capture with a ``CaptureSession`` (one Endpoint Security client per event class), and streams batched events to the
/// Mac Monitor connection that owns the event stream.
///
/// **Ownership:** the first connection to call `start(recording:reply:)` and get capture running owns the event stream
/// (the *sink*) until it goes away. A second Mac Monitor (`open -n`, another user's session) gets `.streamOwned` and
/// can't change recording, subscriptions, the saved mute set, or install updates. It can still read state and check
/// for updates. A start Endpoint Security refuses (`.tooManyClients` while `macmonitor` streams hold clients, say)
/// leaves no owner. When the owner goes away we post ``SensorXPC/sensorReleasedNotification`` so a refused Mac Monitor
/// can claim the stream. ``StreamService`` posts it too when a stream frees its clients.
///
/// **Saved mute set and indicators:** any user's Mac Monitor may change them, administrator or not, while it owns the
/// event stream or nobody does. `macmonitor` changes them as root, or as any user when Settings allows it
/// (``CommandLineAccess``). Capture follows both while it runs, and stamps each event with the indicators it matches.
///
/// **Command line access:** any Mac Monitor may read who can use `macmonitor` without `sudo`. Like the saved mute set,
/// any user's Mac Monitor may change it, administrator or not, while it owns the event stream or nobody does.
///
/// **Field filters:** they travel as ``FieldFilter`` wire names beside event names in `eventSubscriptions(reply:)` and
/// `setSubscription(_:enabled:reply:)`, and like subscriptions only the owner changes them. They're kept in memory,
/// so they return to the defaults (close: only modified files) whenever the Security Extension restarts.
///
/// **Updates:** any user's Mac Monitor may install one, administrator or not, while it owns the event stream or nobody
/// does. The Security Extension downloads the latest release itself and installs it only once Gatekeeper accepts it
/// and it's signed by Swiftly Detecting's team, so the most a caller can do is bring Mac Monitor up to date.
///
/// **Threading:** every piece of state below, and every call into the ``CaptureSession``, happens on `queue`. The
/// Endpoint Security handlers only serialize events (while recording) and hop onto `queue` to buffer them, so each
/// class's events reach Mac Monitor in its client's order.
///
/// **Lifecycle:** only the sink's connection going away stops capture and deletes the ES clients. Any other connection
/// (e.g. an update check that raced the handshake) can come and go without affecting monitoring.
public final class SensorService: NSObject {
    /// Makes the capture session: live, or on fake clients in the tests.
    typealias CaptureMaker = StreamService.CaptureMaker

    /// The Mac Monitor connection that owns the event stream, and the batcher sending events to it.
    struct Sink {
        /// The connection that called `start(recording:reply:)`.
        let connection: NSXPCConnection
        /// Sends events to `connection`. Closed when it goes away.
        let batcher: EventBatcher
    }

    let updates: SensorUpdating
    let queue = DispatchQueue(label: "com.swiftlydetecting.agent.securityextension.sensor")
    let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "SensorService")
    /// Makes the capture session when the stream is claimed.
    let makeCapture: CaptureMaker
    /// Called when the owner goes away, from `queue`.
    let released: () -> Void

    /// The Mac Monitor connection receiving events, and the batcher sending them, if any.
    var sink: Sink?

    /// Capture for the sink, while there is one.
    var capture: CaptureSession?

    /// Mac Monitor's event subscriptions. They outlive a capture session, so a Mac Monitor that reconnects keeps the
    /// ones it chose.
    var subscriptions: [es_event_type_t] = defaultEventSubscriptions

    /// Mac Monitor's field filters. Like `subscriptions`, they outlive a capture session and return to the defaults
    /// when the Security Extension restarts.
    var fieldFilters = Set(defaultFieldFilters)

    /// Endpoint Security's default mutes (``ESMutedPath`` JSON), from the first capture session this process started.
    var appleDefaultMutes: Set<String> = []

    /// The saved mute set, shared with every `macmonitor` stream. Capture follows it while `muteSubscription` is held:
    /// each change is saved, then applied.
    let savedMutes: SavedMuteSet
    var muteSubscription: AnyCancellable?

    /// Who may use `macmonitor` without `sudo`, shared with the ``StreamService``.
    let commandLineAccess: CommandLineAccessStore

    /// The Mac's indicator set, shared with every `macmonitor` stream. Capture follows it while
    /// `indicatorSubscription` is held, and stamps each event with those it matches.
    let savedIndicators: SavedIndicatorSet
    var indicatorSubscription: AnyCancellable?

    /// The live service: capture on live Endpoint Security clients, and the owner going away posts
    /// ``SensorXPC/sensorReleasedNotification``.
    ///
    /// - Parameters:
    ///   - savedMutes: The saved mute set, loaded before the listener starts.
    ///   - savedIndicators: The Mac's indicator set, loaded before the listener starts.
    ///   - commandLineAccess: Who may use `macmonitor` without `sudo`.
    ///   - updates: Checks for and installs releases.
    public convenience init(savedMutes: SavedMuteSet, savedIndicators: SavedIndicatorSet,
                            commandLineAccess: CommandLineAccessStore, updates: SensorUpdating) {
        self.init(savedMutes: savedMutes, savedIndicators: savedIndicators, commandLineAccess: commandLineAccess,
                  updates: updates, makeCapture: { try CaptureSession($0, emit: $1) },
                  released: { notify_post(SensorXPC.sensorReleasedNotification) })
    }

    /// - Parameters:
    ///   - savedMutes: The saved mute set.
    ///   - savedIndicators: The Mac's indicator set.
    ///   - commandLineAccess: Who may use `macmonitor` without `sudo`.
    ///   - updates: Checks for and installs releases.
    ///   - makeCapture: Makes the capture session when the stream is claimed.
    ///   - released: Called when the owner goes away.
    init(savedMutes: SavedMuteSet, savedIndicators: SavedIndicatorSet, commandLineAccess: CommandLineAccessStore,
         updates: SensorUpdating, makeCapture: @escaping CaptureMaker, released: @escaping () -> Void) {
        self.savedMutes = savedMutes
        self.savedIndicators = savedIndicators
        self.commandLineAccess = commandLineAccess
        self.updates = updates
        self.makeCapture = makeCapture
        self.released = released
    }

    /// Configure and activate a Mac Monitor connection the router pinned to ``SensorXPC/agentRequirement``.
    ///
    /// - Parameter connection: The incoming Mac Monitor connection, not yet activated.
    public func accept(_ connection: NSXPCConnection) {
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
    func perform<Reply>(_ reply: @escaping (Reply) -> Void, _ work: @escaping () -> Reply) {
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
    func performForOwner<Reply>(refusing refused: Reply, _ reply: @escaping (Reply) -> Void,
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
    func owns(_ caller: NSXPCConnection?) -> Bool {
        guard let caller, caller === sink?.connection else {
            logger.error("Refusing a control request from a Mac Monitor connection that doesn't own the event stream.")
            return false
        }
        return true
    }
}
