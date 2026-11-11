//
//  SensorClient.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/1/26.
//

import Foundation
import OSLog
import notify


// MARK: - Sensor client
/// Mac Monitor's (agent) side of the XPC connection to the Security Extension (sensor).
///
/// Owns at most one `NSXPCConnection` at a time. The connection is created on first use, and again after it has been
/// invalidated, so callers never manage connection state. Every request goes through
/// ``call(caller:_:completion:)``.
///
/// **Reconnects:** `onSignal` tells the owner when to re-run the idempotent `start(recording:reply:)` handshake:
/// - ``Signal/restarted``: the Security Extension lost its Endpoint Security client. Either the connection was
///   *interrupted* (the extension exited or crashed, and the next message relaunches it on demand), or the extension
///   posted ``SensorXPC/sensorReadyNotification`` once its listener came up. The latter also covers the extension being
///   disabled and re-enabled, which *invalidates* our connection and so never interrupts it.
/// - ``Signal/released``: the Mac Monitor that owned the event stream went away
///   (``SensorXPC/sensorReleasedNotification``), so one that was refused can claim it.
///
/// **Lifetime:** the connection retains the exported `agent` until the connection is invalidated. For Mac Monitor
/// that is the app-lifetime ``EndpointSecurityManager``.
public final class SensorClient {
    /// Guards `connection`. Requests are sent from the main thread, handlers run on the connection's queue.
    private let lock = NSLock()
    private var connection: NSXPCConnection?
    private let agent: AppAgentProtocol
    /// Makes each connection, not yet activated, with its peer pinned.
    private let connect: () -> NSXPCConnection
    private let onSignal: (Signal) -> Void
    /// Our Darwin notification registrations.
    private var notifyTokens: [Int32] = []
    private let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "SensorClient")
    
    /// Why the owner should consider re-running the `start` handshake.
    public enum Signal {
        /// The Security Extension exited, crashed, or (re)launched and has no Endpoint Security client.
        case restarted
        /// The Mac Monitor that owned the event stream went away.
        case released
    }
    
    /// Create a client. No connection is made until the first request.
    ///
    /// - Parameters:
    ///   - agent: The object exported to the Security Extension (receives events and an update's progress).
    ///   - onSignal: Called on the main queue when the owner should consider a new handshake.
    public convenience init(agent: AppAgentProtocol, onSignal: @escaping (Signal) -> Void) {
        self.init(agent: agent, connect: SensorClient.securityExtension, onSignal: onSignal)
    }

    /// Create a client whose connections go where `connect` says. Tests pass one to a listener in the test process.
    ///
    /// - Parameters:
    ///   - agent: The object exported to the Security Extension (receives events and an update's progress).
    ///   - connect: Makes a connection that isn't activated yet.
    ///   - onSignal: Called on the main queue when the owner should consider a new handshake.
    init(agent: AppAgentProtocol, connect: @escaping () -> NSXPCConnection, onSignal: @escaping (Signal) -> Void) {
        self.agent = agent
        self.connect = connect
        self.onSignal = onSignal
        observe(SensorXPC.sensorReadyNotification, as: .restarted)
        observe(SensorXPC.sensorReleasedNotification, as: .released)
    }
    
    deinit {
        notifyTokens.forEach { notify_cancel($0) }
        connection?.invalidate()
    }
    
    /// Forward a Darwin notification posted by the Security Extension to `onSignal`.
    ///
    /// - Parameters:
    ///   - name: The notification name.
    ///   - signal: What it means for the owner.
    private func observe(_ name: String, as signal: Signal) {
        var token: Int32 = NOTIFY_TOKEN_INVALID
        let status = notify_register_dispatch(name, &token, .main) { [weak self] _ in
            self?.logger.log("Received \(name, privacy: .public).")
            self?.onSignal(signal)
        }
        guard status == NOTIFY_STATUS_OK else {
            return logger.error("Unable to register for \(name, privacy: .public): \(status)")
        }
        notifyTokens.append(token)
    }
    
    /// Send one request to the Security Extension.
    ///
    /// NSXPC guarantees that exactly one of the reply block or the proxy's error handler runs for a message with a
    /// reply block, so `completion` is always called exactly once.
    ///
    /// ```swift
    /// sensor.call { $0.appleMuteSet(reply: $1) } completion: { paths in
    ///     guard let paths else { return } // The request failed and has been logged.
    /// }
    /// ```
    ///
    /// - Parameters:
    ///   - caller: Names the request in the log when it fails. Defaults to the calling function.
    ///   - request: Sends the message to the proxy, passing the reply block through.
    ///   - completion: Called on the main queue with the reply, or `nil` if the request failed.
    public func call<Reply>(
        caller: String = #function,
        _ request: (SensorProtocol, @escaping (Reply) -> Void) -> Void,
        completion: @escaping (Reply?) -> Void = { _ in }
    ) {
        let deliver: (Reply?) -> Void = { reply in
            DispatchQueue.main.async { completion(reply) }
        }
        
        let proxy = liveConnection.remoteObjectProxyWithErrorHandler { [logger] error in
            logger.error(
                "XPC request \(caller, privacy: .public) failed: \(error.localizedDescription, privacy: .public)"
            )
            deliver(nil)
        }
        guard let sensor = proxy as? SensorProtocol else {
            logger.fault("The remote object proxy does not conform to SensorProtocol!")
            deliver(nil)
            return
        }
        
        request(sensor) { deliver($0) }
    }

    /// Send one request on a connection of its own, closed once it's answered: for a request the Security Extension
    /// may not know.
    ///
    /// NSXPC closes the connection that sends a message its peer's interface doesn't have. On the connection
    /// ``call(caller:_:completion:)`` uses, that would end Mac Monitor's event stream. Here it closes only this one,
    /// and `completion` gets `nil`. The Security Extension doesn't know this connection as the one that owns the
    /// event stream, so only requests any caller may make belong here. A change only the owner may make goes on
    /// ``call(caller:_:completion:)`` once a probe has answered (``SensorSupport``).
    ///
    /// - Parameters:
    ///   - caller: Names the request in the log when it fails. Defaults to the calling function.
    ///   - request: Sends the message to the proxy, passing the reply block through.
    ///   - completion: Called on the main queue with the reply, or `nil` if the request failed.
    public func probe<Reply>(
        caller: String = #function,
        _ request: (SensorProtocol, @escaping (Reply) -> Void) -> Void,
        completion: @escaping (Reply?) -> Void
    ) {
        send(caller: caller, request, once: connect(), completion: completion)
    }

    /// A connection to our own Security Extension's Mach service, not yet activated. A mismatched peer invalidates it.
    ///
    /// - Returns: The connection.
    private static func securityExtension() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: SensorXPC.machServiceName, options: [])
        connection.setCodeSigningRequirement(SensorXPC.sensorRequirement)
        return connection
    }

    /// Send one request on `connection`, then invalidate it.
    ///
    /// - Parameters:
    ///   - caller: Names the request in the log when it fails.
    ///   - request: Sends the message to the proxy, passing the reply block through.
    ///   - connection: A connection that isn't activated yet. Tests pass one to a listener in the test process.
    ///   - completion: Called on the main queue with the reply, or `nil` if the request failed.
    func send<Reply>(
        caller: String,
        _ request: (SensorProtocol, @escaping (Reply) -> Void) -> Void,
        once connection: NSXPCConnection,
        completion: @escaping (Reply?) -> Void
    ) {
        connection.remoteObjectInterface = SensorXPC.sensorInterface
        connection.activate()
        let deliver: (Reply?) -> Void = { reply in
            connection.invalidate()
            DispatchQueue.main.async { completion(reply) }
        }
        let proxy = connection.remoteObjectProxyWithErrorHandler { [logger] error in
            logger.log("""
                The probe \(caller, privacy: .public) got no answer: \(error.localizedDescription, privacy: .public)
                """)
            deliver(nil)
        }
        guard let sensor = proxy as? SensorProtocol else {
            deliver(nil)
            return
        }
        request(sensor) { deliver($0) }
    }

    /// The current connection, created on demand.
    private var liveConnection: NSXPCConnection {
        lock.withLock {
            if let connection { return connection }
            
            let newConnection = connect()
            configure(newConnection)
            newConnection.activate()
            connection = newConnection
            return newConnection
        }
    }
    
    /// Set up a new connection to the Security Extension before it's activated.
    ///
    /// The handlers run on the connection's queue. An interruption hops to the main queue before it reaches
    /// `onSignal`, since the owner keeps its pending signals there.
    ///
    /// - Parameter newConnection: The connection. Tests pass one that's never activated.
    func configure(_ newConnection: NSXPCConnection) {
        newConnection.remoteObjectInterface = SensorXPC.sensorInterface
        newConnection.exportedInterface = SensorXPC.agentInterface
        newConnection.exportedObject = agent
        
        newConnection.interruptionHandler = { [weak self] in
            self?.logger.error("The Security Extension exited or crashed.")
            DispatchQueue.main.async { self?.onSignal(.restarted) }
        }
        /// Invalidation is final. Forget this connection so the next request creates a new one.
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            self?.logger.error("The connection to the Security Extension was invalidated.")
            self?.forget(newConnection)
        }
    }
    
    /// Drop `invalidated` if it is still the current connection.
    ///
    /// Comparing identity means a late callback from an old connection can never discard a newer one.
    ///
    /// - Parameter invalidated: The connection whose invalidation handler fired.
    private func forget(_ invalidated: NSXPCConnection?) {
        lock.withLock {
            if connection === invalidated { connection = nil }
        }
    }
}
