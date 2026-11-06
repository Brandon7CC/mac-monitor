//
//  StreamService.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import OSLog
import os
import notify


// MARK: - Stream service
/// Serves `macmonitor` (Security Extension context): root's, and any user's when Settings allows it
/// (``CommandLineAccess``).
///
/// Every connection the router hands it gets its own ``StreamSession``: its own queue, capture session (one Endpoint
/// Security client per event class), mutes, and batcher. So nothing a `macmonitor` does, or fails to do, touches Mac
/// Monitor's stream, who owns it, or another `macmonitor`. At most ``StreamSlots/capacity`` streams run at once.
///
/// The exported object is the session, never `SensorService`, so a `macmonitor` connection can't reach
/// ``SensorProtocol``.
public final class StreamService {
    /// Makes a stream's capture session: live, or on fake clients in the tests.
    typealias CaptureMaker = (CaptureConfiguration, @escaping (CapturedEvent) -> Void) throws -> CaptureSession
    
    /// The saved mute set every stream applies unless asked not to.
    let savedMutes: SavedMuteSet
    /// The streams running.
    let slots: StreamSlots
    /// The Security Extension's version, such as "3.0.0 (1)".
    let sensorVersion: String
    /// What the caller may do. Asked on the thread delivering each request.
    let grant: (NSXPCConnection?) -> CommandLineGrant
    /// Makes each stream's capture session.
    let makeCapture: CaptureMaker
    /// Called when a stream that held Endpoint Security clients closes, from its queue: Endpoint Security may have
    /// refused Mac Monitor's clients while the stream held its own.
    let released: () -> Void
    /// The last session's number.
    private let sessionNumbers = OSAllocatedUnfairLock(initialState: UInt64(0))
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "StreamService")
    
    /// An admission rule: what a connection's effective user may do at the level `access` reads at each request.
    /// Asked on the thread delivering each request, where the connection is `NSXPCConnection.current()`. No
    /// connection may do nothing.
    ///
    /// - Parameter access: Reads the level, such as ``CommandLineAccessStore/access``.
    /// - Returns: The rule.
    public static func granting(_ access: @escaping () -> CommandLineAccess)
        -> (NSXPCConnection?) -> CommandLineGrant {
        { connection in
            guard let connection else { return .refused(CommandLineAccess.needsRoot) }
            return access().grant(forEffectiveUser: connection.effectiveUserIdentifier)
        }
    }
    
    /// The default rule: only root.
    public static let rootOnly = granting { .rootOnly }
    
    /// The live service: ``SensorXPC/maxCommandLineStreams`` streams on live Endpoint Security clients, for root and,
    /// when Settings allows it, any user. A stream that closes posts ``SensorXPC/sensorReleasedNotification``,
    /// so a Mac Monitor that Endpoint Security refused (`.tooManyClients`) tries again.
    ///
    /// - Parameters:
    ///   - savedMutes: The saved mute set, shared with Mac Monitor's capture.
    ///   - access: Who may use `macmonitor` without `sudo`, read at each request.
    public convenience init(savedMutes: SavedMuteSet, access: CommandLineAccessStore) {
        self.init(savedMutes: savedMutes, slots: StreamSlots(capacity: SensorXPC.maxCommandLineStreams),
                  sensorVersion: Self.version(of: .main), grant: Self.granting { access.access },
                  makeCapture: { try CaptureSession($0, emit: $1) },
                  released: { notify_post(SensorXPC.sensorReleasedNotification) })
    }
    
    /// - Parameters:
    ///   - savedMutes: The saved mute set.
    ///   - slots: Caps the streams.
    ///   - sensorVersion: The Security Extension's version.
    ///   - grant: What the caller may do.
    ///   - makeCapture: Makes each stream's capture session.
    ///   - released: Called when a stream that held Endpoint Security clients closes.
    init(savedMutes: SavedMuteSet, slots: StreamSlots, sensorVersion: String,
         grant: @escaping (NSXPCConnection?) -> CommandLineGrant, makeCapture: @escaping CaptureMaker,
         released: @escaping () -> Void = {}) {
        self.savedMutes = savedMutes
        self.slots = slots
        self.sensorVersion = sensorVersion
        self.grant = grant
        self.makeCapture = makeCapture
        self.released = released
    }
    
    /// Configure and activate a connection the router pinned to `macmonitor`'s requirement.
    ///
    /// The invalidation handler keeps the session until it has closed: the connection releases its handlers once it's
    /// invalidated, which breaks the cycle through the session's batcher.
    ///
    /// - Parameter connection: A connection from `macmonitor`, not yet activated.
    public func accept(_ connection: NSXPCConnection) {
        let number = sessionNumbers.withLock { number -> UInt64 in
            number += 1
            return number
        }
        let session = StreamSession(connection: connection, service: self, number: number)
        connection.exportedInterface = SensorXPC.streamInterface
        connection.exportedObject = session
        connection.remoteObjectInterface = SensorXPC.streamReaderInterface
        connection.invalidationHandler = { session.close() }
        connection.activate()
    }
    
    /// A bundle's version as `macmonitor` shows it.
    ///
    /// - Parameter bundle: The bundle, such as the Security Extension's.
    /// - Returns: Its short version and build, such as "3.0.0 (1)".
    static func version(of bundle: Bundle) -> String {
        version(from: bundle.infoDictionary ?? [:])
    }
    
    /// A version as `macmonitor` shows it, and compares its own with the Security Extension's: one format for both,
    /// so they only differ when the versions do.
    ///
    /// - Parameter info: An `Info.plist`'s keys.
    /// - Returns: Its short version and build, such as "3.0.0 (1)", each "unknown" if it's missing.
    public static func version(from info: [String: Any]) -> String {
        let short = info["CFBundleShortVersionString"] as? String ?? "unknown"
        let build = info["CFBundleVersion"] as? String ?? "unknown"
        return "\(short) (\(build))"
    }
}
