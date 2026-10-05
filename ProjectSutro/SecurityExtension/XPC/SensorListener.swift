//
//  SensorListener.swift
//  SecurityExtension
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import OSLog
import notify
import SutroESFramework


// MARK: - Sensor listener
/// The Security Extension's one listener, on `SensorXPC.machServiceName`.
///
/// It admits Mac Monitor or `macmonitor` (`SensorXPC.listenerRequirement`), and ``SensorListenerRouter`` hands each
/// connection to exactly one of them by the effective user that connected: root's go to the ``StreamService``,
/// everyone else's to the ``SensorService``.
final class SensorListener: NSObject {
    private let listener = NSXPCListener(machServiceName: SensorXPC.machServiceName)
    private let router: SensorListenerRouter<NSXPCConnection>
    private let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "SensorListener")
    
    /// - Parameters:
    ///   - app: Serves Mac Monitor. Kept for the life of the listener.
    ///   - commandLine: Serves `macmonitor`. Kept for the life of the listener.
    init(app: SensorService, commandLine: StreamService) {
        router = SensorListenerRouter(app: app.accept, commandLine: commandLine.accept)
    }
    
    /// Start accepting connections, then announce that we're ready.
    ///
    /// The code signing requirement is enforced by the listener, so a peer that is neither Mac Monitor nor
    /// `macmonitor` is rejected before ``listener(_:shouldAcceptNewConnection:)`` is consulted.
    ///
    /// Posting `SensorXPC.sensorReadyNotification` tells a running Mac Monitor to redo its handshake: after a crash,
    /// or after the extension was disabled and re-enabled, this process has no ES client until it does.
    func activate() {
        EventSpool.removeLeftovers()
        let declaredService = Bundle.main.object(forInfoDictionaryKey: "NSEndpointSecurityMachServiceName") as? String
        if declaredService != SensorXPC.machServiceName {
            logger.fault("""
                NSEndpointSecurityMachServiceName (\(declaredService ?? "missing", privacy: .public)) does not match \
                SensorXPC.machServiceName (\(SensorXPC.machServiceName, privacy: .public))!
                """)
        }
        
        listener.setConnectionCodeSigningRequirement(SensorXPC.listenerRequirement)
        listener.delegate = self
        listener.activate()
        logger.log("🔒 Listening for Mac Monitor and macmonitor on \(SensorXPC.machServiceName, privacy: .public)")
        notify_post(SensorXPC.sensorReadyNotification)
    }
}


// MARK: - Listener delegate
extension SensorListener: NSXPCListenerDelegate {
    /// Route a connection that has already passed `SensorXPC.listenerRequirement`.
    ///
    /// - Parameters:
    ///   - listener: Our Mach service listener.
    ///   - connection: The incoming connection.
    /// - Returns: Always `true`. Peers that fail the code signing requirement never reach the delegate, and the router
    ///   pins each connection to its role's requirement before it's activated.
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        if router.route(connection) == .commandLine {
            logger.log("Accepted a macmonitor connection (pid \(connection.processIdentifier), euid 0).")
        }
        return true
    }
}
