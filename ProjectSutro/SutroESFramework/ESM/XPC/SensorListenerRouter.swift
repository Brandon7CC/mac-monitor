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
    
    /// The peer's process ID. Only a hint, since it can be reused (``PeerSignature``).
    var processIdentifier: pid_t { get }
    
    /// Pin the code signing requirement the peer must satisfy. NSXPC checks it against the peer's audit token on every
    /// message and invalidates the connection on the first that fails.
    ///
    /// - Parameter requirement: A code signing requirement string.
    func setCodeSigningRequirement(_ requirement: String)
}


extension NSXPCConnection: PeerConnection {}


// MARK: - Router
/// Routes each connection the Security Extension's listener accepts to exactly one role: root's, and anyone's whose
/// process is signed as `macmonitor`, go to `macmonitor`, and everyone else's to Mac Monitor.
///
/// The listener admits either program (``SensorXPC/listenerRequirement``). The router then pins the connection to its
/// role's requirement before the role's endpoint configures and activates it, so:
/// - a process signed as Mac Monitor that the router took for `macmonitor` (root, or a reused process ID) reaches
///   neither ``StreamProtocol`` nor ``SensorProtocol``: it's offered `macmonitor`'s interface and cut off on its
///   first message. Nothing runs Mac Monitor as root;
/// - a process signed as `macmonitor` that the router took for Mac Monitor is cut off the same way.
///
/// The `macmonitor` role grants nothing by itself. Whether a request may stream or change mutes is decided per
/// request, by the effective user and ``CommandLineAccess`` (``StreamService``), so a non-root `macmonitor` gets a
/// refusal that says why rather than a connection that's cut off.
///
/// The effective user is the kernel's, from the audit token, never the process ID. `macmonitor` refuses to run
/// set-user-ID, so its real and effective users match, and it never changes either after connecting.
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
    /// Is a peer that isn't root signed as `macmonitor`? A hint: the pin decides (``PeerSignature``).
    private let signedAsCommandLine: (Connection) -> Bool
    
    /// - Parameters:
    ///   - app: Configures and activates a Mac Monitor connection.
    ///   - commandLine: Configures and activates a `macmonitor` connection.
    ///   - signedAsCommandLine: Is a peer that isn't root signed as `macmonitor`? The Security Extension passes
    ///     ``PeerSignature/isCommandLine(_:)``. Without it, only root reaches `macmonitor`'s endpoint.
    public init(app: @escaping (Connection) -> Void, commandLine: @escaping (Connection) -> Void,
                signedAsCommandLine: @escaping (Connection) -> Bool = { _ in false }) {
        self.app = app
        self.commandLine = commandLine
        self.signedAsCommandLine = signedAsCommandLine
    }
    
    /// The role of a connection.
    ///
    /// - Parameters:
    ///   - euid: The peer's effective user ID.
    ///   - signedAsCommandLine: Is the peer's process signed as `macmonitor`?
    /// - Returns: ``Role-swift.enum/commandLine`` for root or a process signed as `macmonitor`, else
    ///   ``Role-swift.enum/app``.
    public static func role(forEffectiveUser euid: uid_t, signedAsCommandLine: Bool = false) -> Role {
        euid == 0 || signedAsCommandLine ? .commandLine : .app
    }
    
    /// Pin a connection to its role's requirement, then hand it to the role's endpoint.
    ///
    /// - Parameter connection: A connection the listener accepted, not yet activated.
    /// - Returns: Its role.
    @discardableResult
    public func route(_ connection: Connection) -> Role {
        let euid = connection.effectiveUserIdentifier
        let role = Self.role(forEffectiveUser: euid, signedAsCommandLine: euid != 0 && signedAsCommandLine(connection))
        connection.setCodeSigningRequirement(role.requirement)
        switch role {
        case .app: app(connection)
        case .commandLine: commandLine(connection)
        }
        return role
    }
}
