//
//  SensorListenerRouter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Peer connection
/// What the Security Extension reads and sets on an incoming connection to route it: an `NSXPCConnection`, or a test's
/// fake.
public protocol PeerConnection: AnyObject {
    /// The peer's effective user ID, which the kernel recorded in its audit token when it connected.
    var effectiveUserIdentifier: uid_t { get }
    
    /// Pin the code signing requirement the peer must satisfy. NSXPC checks it against the peer's audit token on every
    /// message and invalidates the connection on the first that fails.
    ///
    /// - Parameter requirement: A code signing requirement string.
    func setCodeSigningRequirement(_ requirement: String)
}


extension NSXPCConnection: PeerConnection {}


// MARK: - Router
/// Routes each connection the Security Extension's listener accepts to exactly one role, by the effective user that
/// connected: root can only be `macmonitor`, and anyone else only Mac Monitor.
///
/// The listener admits either program (``SensorXPC/listenerRequirement``). The router then pins the connection to its
/// role's requirement before the role's endpoint configures and activates it, so:
/// - a non-root process signed as `macmonitor` reaches neither ``StreamProtocol`` nor ``SensorProtocol``: it's offered
///   Mac Monitor's interface and cut off on its first message;
/// - a root process signed as Mac Monitor is cut off the same way. Nothing runs Mac Monitor as root.
///
/// The effective user is the kernel's, from the audit token, never the process ID. `macmonitor` refuses to run with
/// a real user other than root, so it can't drop privileges after connecting.
public struct SensorListenerRouter<Connection: PeerConnection> {
    /// Who a connection serves.
    public enum Role: Equatable, Sendable {
        /// Mac Monitor: ``SensorProtocol``.
        case app
        /// `macmonitor`: ``StreamProtocol``.
        case commandLine
        
        /// The code signing requirement a connection in this role is pinned to.
        public var requirement: String {
            switch self {
            case .app: return SensorXPC.agentRequirement
            case .commandLine: return SensorXPC.commandLineRequirement
            }
        }
    }
    
    /// Configures and activates a Mac Monitor connection.
    private let app: (Connection) -> Void
    /// Configures and activates a `macmonitor` connection.
    private let commandLine: (Connection) -> Void
    
    /// - Parameters:
    ///   - app: Configures and activates a Mac Monitor connection.
    ///   - commandLine: Configures and activates a `macmonitor` connection.
    public init(app: @escaping (Connection) -> Void, commandLine: @escaping (Connection) -> Void) {
        self.app = app
        self.commandLine = commandLine
    }
    
    /// The role of a connection from an effective user.
    ///
    /// - Parameter euid: The peer's effective user ID.
    /// - Returns: ``Role-swift.enum/commandLine`` for root, else ``Role-swift.enum/app``.
    public static func role(forEffectiveUser euid: uid_t) -> Role {
        euid == 0 ? .commandLine : .app
    }
    
    /// Pin a connection to its role's requirement, then hand it to the role's endpoint.
    ///
    /// - Parameter connection: A connection the listener accepted, not yet activated.
    /// - Returns: Its role.
    @discardableResult
    public func route(_ connection: Connection) -> Role {
        let role = Self.role(forEffectiveUser: connection.effectiveUserIdentifier)
        connection.setCodeSigningRequirement(role.requirement)
        switch role {
        case .app: app(connection)
        case .commandLine: commandLine(connection)
        }
        return role
    }
}
