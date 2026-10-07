//
//  SensorXPC.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/1/26.
//

import Foundation


// MARK: - XPC contract
/// The XPC contract between Mac Monitor (the agent), `macmonitor` (the command line tool), and the Security Extension
/// (the sensor).
///
/// This is the only XPC source the three processes share: it ships in `SutroESFramework`, which they all link. The
/// Security Extension exports ``SensorProtocol`` to Mac Monitor and ``StreamProtocol`` to `macmonitor`, on one Mach
/// service. To receive events, Mac Monitor exports ``AgentProtocol`` on its connection, and `macmonitor`
/// ``StreamReaderProtocol``, which adds what it tells the user while it streams.
///
/// **Implementations:**
/// - Agent: ``SensorClient``
/// - Command line: ``StreamClient``, in `macmonitor`
/// - Sensor: `SensorService` and ``StreamService``, behind `SensorListener` in the Security Extension target
///
public enum SensorXPC {
    /// The team identifier that signs Mac Monitor, the Security Extension, and the update packages.
    public static let teamID: String = "4HMJQ7V3SX"
    
    /// The Mach service the Security Extension listens on.
    ///
    /// - Important: Must match `NSEndpointSecurityMachServiceName` in the Security Extension's `Info.plist`.
    ///   The Security Extension logs a fault at launch if they ever drift apart.
    public static let machServiceName: String = "\(teamID).com.swiftlydetecting.agent.securityextension.xpc"
    
    /// Darwin notification the Security Extension posts once its listener is up (at launch, after a crash, or after the
    /// extension is re-enabled). Mac Monitor re-runs the idempotent `start` handshake when it sees it.
    ///
    /// Anyone can post a Darwin notification, so this is only ever a hint: the handshake itself runs over a connection
    /// that verifies the Security Extension's code signature, and a spoofed post just causes a harmless re-handshake (at
    /// most one a second, however fast they're posted).
    public static let sensorReadyNotification: String = "com.swiftlydetecting.agent.securityextension.ready"
    
    /// Darwin notification the Security Extension posts when the Mac Monitor that owned the event stream goes away,
    /// or a `macmonitor` stream frees its Endpoint Security clients. A Mac Monitor that was refused, by the owner
    /// (`.streamOwned`) or by Endpoint Security (`.tooManyClients`), re-runs the `start` handshake to claim the stream.
    /// Like ``sensorReadyNotification`` it's only a hint.
    public static let sensorReleasedNotification: String = "com.swiftlydetecting.agent.securityextension.released"
    
    /// The most event batches the Security Extension sends before waiting for Mac Monitor's replies.
    ///
    /// Mac Monitor only replies once a batch is saved to Core Data, so it must flush by the time half of this window is
    /// waiting (see `EndpointSecurityManager.receive(events:reply:)`), however few events survive its filters.
    public static let maxBatchesInFlight: Int = 16
    
    /// The code signing requirement for Mac Monitor: what the Security Extension enforces on every connection that
    /// isn't root's.
    public static let agentRequirement: String = requirement(for: "com.swiftlydetecting.agent")
    
    /// The code signing requirement for `macmonitor`: what the Security Extension enforces on every connection from
    /// root.
    public static let commandLineRequirement: String = requirement(for: "com.swiftlydetecting.agent.cli")
    
    /// What the Security Extension's listener admits: Mac Monitor or `macmonitor`. Each connection is then pinned to
    /// exactly one of them by its effective user (``SensorListenerRouter``).
    public static let listenerRequirement: String = either(agentRequirement, commandLineRequirement)
    
    /// The most `macmonitor stream` sessions at once. Each holds ``CaptureSession/clientsPerSession`` Endpoint
    /// Security clients, and the system's clients are shared with every Endpoint Security product: Mac Monitor and
    /// three streams hold 12.
    public static let maxCommandLineStreams: Int = 3
    
    /// The code signing requirement Mac Monitor enforces on the Security Extension.
    public static let sensorRequirement: String = requirement(for: "com.swiftlydetecting.agent.securityextension")
    
    /// The interface the Security Extension exports and Mac Monitor calls.
    public static var sensorInterface: NSXPCInterface { NSXPCInterface(with: SensorProtocol.self) }
    
    /// The interface Mac Monitor exports and the Security Extension calls.
    public static var agentInterface: NSXPCInterface { NSXPCInterface(with: AgentProtocol.self) }
    
    /// The interface `macmonitor` exports and the Security Extension calls.
    public static var streamReaderInterface: NSXPCInterface { NSXPCInterface(with: StreamReaderProtocol.self) }
    
    /// The interface the Security Extension exports to `macmonitor`, and only to `macmonitor`.
    public static var streamInterface: NSXPCInterface { NSXPCInterface(with: StreamProtocol.self) }
    
    /// Build the code signing requirement for one of our signing identifiers.
    ///
    /// **Using the following resources:**
    /// - [Developer Forums](https://developer.apple.com/forums/thread/681053)
    /// - [Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
    ///
    /// We're going to check for the following in our requirements string:
    /// (1) `anchor apple generic`: Any code signed with any code signing identity issued by Apple (AND)
    /// (2) `identifier`: The expected code signing identifier (AND)
    /// (3) `1[field.1.2.840.113635.100.6.2.6]`: Issued by an Apple Developer ID (AND)
    /// (4) `leaf[field.1.2.840.113635.100.6.1.13]`: Leaf certificate is a Developer ID App (AND)
    /// (5) `certificate leaf[subject.OU]`: Swiftly Detecting team ID
    ///
    /// - Parameter identifier: The code signing identifier the peer must carry.
    /// - Returns: A requirement string suitable for `NSXPCListener` / `NSXPCConnection`.
    private static func requirement(for identifier: String) -> String {
#if COMMUNITY_BUILD
        return communityRequirement(for: identifier)
#else
        return developerIDRequirement(for: identifier)
#endif
    }
    
    /// The requirement a Developer ID build enforces: (1) to (5) above.
    ///
    /// - Parameter identifier: The code signing identifier the peer must carry.
    /// - Returns: The requirement string.
    static func developerIDRequirement(for identifier: String) -> String {
        "anchor apple generic and identifier \"\(identifier)\""
            + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
            + " and certificate leaf[subject.OU] = \"\(teamID)\""
    }
    
    /// The requirement a Community build enforces. Community builds are ad-hoc signed (see `Community.xcconfig`), so
    /// there is no certificate chain or team ID to pin against: only the signing identifier is enforced. Never ship a
    /// build that uses it.
    ///
    /// - Parameter identifier: The code signing identifier the peer must carry.
    /// - Returns: The requirement string.
    static func communityRequirement(for identifier: String) -> String {
        "identifier \"\(identifier)\""
    }
    
    /// A requirement that either of two requirements satisfies.
    ///
    /// - Parameters:
    ///   - first: A requirement string.
    ///   - second: Another requirement string.
    /// - Returns: The requirement string.
    static func either(_ first: String, _ second: String) -> String {
        "(\(first)) or (\(second))"
    }
}


// MARK: - SensorProtocol
/// Exported by the Security Extension (sensor) and called by Mac Monitor (agent).
///
/// Every request carries a reply block, even when the agent ignores the result. NSXPC guarantees that exactly one of
/// the reply block or the proxy's error handler runs for such a message, which lets ``SensorClient`` treat every
/// request the same way: log the failure and hand back a fallback value.
///
/// Mute types travel as their `ES_MUTE_PATH_TYPE_*` string names and events travel as their `ES_EVENT_TYPE_*`
/// string names (see `getMuteCaseString(muteType:)` and `eventTypeToString(from:)`), inside versioned JSON for the
/// saved mute set (``MuteRequest``, ``MuteReply``).
@objc public protocol SensorProtocol {
    // MARK: Lifecycle
    /// Claim the event stream for the calling connection and ensure capture is running (one Endpoint Security client
    /// per event class).
    ///
    /// The first connection to call this and get capture running owns the event stream until it goes away. Any other
    /// connection is refused with `.streamOwned`, and the calls below that change monitoring reply with `false` to it.
    ///
    /// Idempotent: the owner calling it again (e.g. after the Security Extension restarts) re-handshakes and only
    /// starts capture when it isn't running.
    ///
    /// - Parameters:
    ///   - recording: Should events be serialized and streamed to the caller right away?
    ///   - reply: The result of creating (or reusing) the Endpoint Security clients, such as `.tooManyClients` when
    ///     the system has too many, or `.streamOwned` if another connection owns the event stream.
    func start(recording: Bool, reply: @escaping (NewClientResult) -> Void)
    
    /// Start or stop serializing events. While stopped the Security Extension does no per-event work.
    ///
    /// - Parameters:
    ///   - enabled: `true` to stream events to the agent.
    ///   - reply: `true` if capture is running, or `false` if the caller doesn't own the event stream.
    func setRecording(_ enabled: Bool, reply: @escaping (Bool) -> Void)
    
    // MARK: Event subscriptions
    /// The event types the Endpoint Security clients are subscribed to.
    ///
    /// - Parameter reply: `ES_EVENT_TYPE_*` names.
    func eventSubscriptions(reply: @escaping ([String]) -> Void)
    
    /// Subscribe to, or unsubscribe from, a single event type.
    ///
    /// - Parameters:
    ///   - event: The `ES_EVENT_TYPE_*` name.
    ///   - enabled: `true` to subscribe, `false` to unsubscribe.
    ///   - reply: `true` if Endpoint Security accepted the request, or `false` if the caller doesn't own the event stream.
    func setSubscription(_ event: String, enabled: Bool, reply: @escaping (Bool) -> Void)
    
    // MARK: Path muting
    /// Read or change the saved mute set: the one set of path mutes the Security Extension keeps on disk and applies
    /// to Mac Monitor's capture and to every `macmonitor stream` without `--no-mutes`.
    ///
    /// Any Mac Monitor can list it. Only an administrator's can change it (others get `.notAdministrator`), and only
    /// while it owns the event stream or nobody does (others get `.refused`). Every reply says which
    /// (``MuteReply/access``).
    ///
    /// - Parameters:
    ///   - request: A JSON encoded ``MuteRequest`` (at most ``MuteLimits/maxFileBytes``).
    ///   - reply: A JSON encoded ``MuteReply``.
    func mutes(_ request: Data, reply: @escaping (Data) -> Void)
    
    /// The paths Apple mutes by default, captured when the Security Extension first started capture.
    ///
    /// - Parameter reply: JSON serializations of ``ESMutedPath``.
    func appleMuteSet(reply: @escaping ([String]) -> Void)
    
    // MARK: Updates
    /// Check GitHub for a newer release of Mac Monitor.
    ///
    /// - Parameter reply: A JSON encoded ``UpdateDetails`` or `nil` when no update is available or the check failed.
    func checkForUpdate(reply: @escaping (Data?) -> Void)
    
    /// Download, verify, and install the latest release.
    ///
    /// The Security Extension resolves the package itself. Nothing about the package comes from the caller.
    ///
    /// - Parameter reply: `true` if the update was installed, or `false` if another connection owns the event stream.
    func installUpdate(reply: @escaping (Bool) -> Void)

    // MARK: Command line tool
    /// Install or remove `/usr/local/bin/macmonitor` as root.
    ///
    /// The Security Extension only acts when the authorization holds ``CommandLineToolAuthorization/rightName``, which
    /// means an administrator approved this change. The link's directory is always `/usr/local/bin`.
    ///
    /// - Parameters:
    ///   - action: `install` or `remove` (``CommandLineToolLink/Action``).
    ///   - tool: The tool to link, or empty for a removal.
    ///   - expected: What Settings saw at the link's path, or empty for nothing.
    ///   - authorization: The authorization's external form (``CommandLineToolAuthorization/requestApproval(prompt:)``).
    ///   - reply: A ``CommandLineToolLinker/Outcome`` raw value.
    func changeCommandLineTool(action: String, tool: String, expected: String, authorization: Data,
                               reply: @escaping (Int) -> Void)
}


// MARK: - AgentProtocol
/// Exported by Mac Monitor (agent) and called by the Security Extension (sensor).
@objc public protocol AgentProtocol {
    /// Deliver a batch of events to Mac Monitor.
    ///
    /// The Security Extension limits how many batches it has in flight, so replying only once the batch's events are
    /// saved gives it back-pressure when Mac Monitor falls behind (it then spools to disk rather than Mac Monitor's
    /// memory growing).
    ///
    /// - Parameters:
    ///   - events: JSON serializations of `Message`, oldest first.
    ///   - reply: Call once the batch's events have been saved (or turned out to need no saving).
    func receive(events: [Data], reply: @escaping () -> Void)
}


// MARK: - StreamReaderProtocol
/// Exported by `macmonitor` (command line) and called by the Security Extension (sensor): a stream's batches, as Mac
/// Monitor receives them, and what `macmonitor` tells the user while it streams.
@objc public protocol StreamReaderProtocol: AgentProtocol {
    /// The saved mute set changed while the stream follows it. The stream no longer shows what the new set mutes,
    /// and muted events never show as lost, so `macmonitor` says so.
    ///
    /// - Parameter change: A JSON encoded ``MuteSetChange``.
    func savedMutesChanged(_ change: Data)
}
