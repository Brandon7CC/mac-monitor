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
/// Serves `sudo macmonitor` (Security Extension context).
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
    /// The Security Extension's version, such as "2.2.0 (1)".
    let sensorVersion: String
    /// Is the caller allowed? Asked on the thread delivering each request: root only.
    let admits: (NSXPCConnection?) -> Bool
    /// Makes each stream's capture session.
    let makeCapture: CaptureMaker
    /// Called when a stream that held Endpoint Security clients closes, from its queue: Endpoint Security may have
    /// refused Mac Monitor's clients while the stream held its own.
    let released: () -> Void
    /// The last session's number.
    private let sessionNumbers = OSAllocatedUnfairLock(initialState: UInt64(0))
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension", category: "StreamService")
    
    /// The live service: ``SensorXPC/maxCommandLineStreams`` streams on live Endpoint Security clients, for root only.
    /// A stream that closes posts ``SensorXPC/sensorReleasedNotification``, so a Mac Monitor that Endpoint Security
    /// refused (`.tooManyClients`) tries again.
    ///
    /// - Parameter savedMutes: The saved mute set, shared with Mac Monitor's capture.
    public convenience init(savedMutes: SavedMuteSet) {
        self.init(savedMutes: savedMutes, slots: StreamSlots(capacity: SensorXPC.maxCommandLineStreams),
                  sensorVersion: Self.version(of: .main), admits: { $0?.effectiveUserIdentifier == 0 },
                  makeCapture: { try CaptureSession($0, emit: $1) },
                  released: { notify_post(SensorXPC.sensorReleasedNotification) })
    }
    
    /// - Parameters:
    ///   - savedMutes: The saved mute set.
    ///   - slots: Caps the streams.
    ///   - sensorVersion: The Security Extension's version.
    ///   - admits: Is the caller allowed?
    ///   - makeCapture: Makes each stream's capture session.
    ///   - released: Called when a stream that held Endpoint Security clients closes.
    init(savedMutes: SavedMuteSet, slots: StreamSlots, sensorVersion: String,
         admits: @escaping (NSXPCConnection?) -> Bool, makeCapture: @escaping CaptureMaker,
         released: @escaping () -> Void = {}) {
        self.savedMutes = savedMutes
        self.slots = slots
        self.sensorVersion = sensorVersion
        self.admits = admits
        self.makeCapture = makeCapture
        self.released = released
    }
    
    /// Configure and activate a connection the router pinned to `macmonitor`'s requirement.
    ///
    /// The invalidation handler keeps the session until it has closed: the connection releases its handlers once it's
    /// invalidated, which breaks the cycle through the session's batcher.
    ///
    /// - Parameter connection: A connection from root, not yet activated.
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
    /// - Returns: Its short version and build, such as "2.2.0 (1)".
    static func version(of bundle: Bundle) -> String {
        version(from: bundle.infoDictionary ?? [:])
    }
    
    /// A version as `macmonitor` shows it, and compares its own with the Security Extension's: one format for both,
    /// so they only differ when the versions do.
    ///
    /// - Parameter info: An `Info.plist`'s keys.
    /// - Returns: Its short version and build, such as "2.2.0 (1)", each "unknown" if it's missing.
    public static func version(from info: [String: Any]) -> String {
        let short = info["CFBundleShortVersionString"] as? String ?? "unknown"
        let build = info["CFBundleVersion"] as? String ?? "unknown"
        return "\(short) (\(build))"
    }
}
