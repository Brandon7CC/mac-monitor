//
//  MessageSerializer.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Serializing
/// What a capture lane hands its serializer with each message.
struct LaneContext {
    /// The lane's client.
    let eventClass: EventClass
    /// The Sensor ID to stamp on the event.
    let sensorID: String
    /// The lane's own encoder. Only one thread uses it at a time.
    let encoder: StreamingJSONEncoder
    /// The executables of the processes the lane's events have named, for the launched-by parents it stamps. The lane's
    /// own: only one thread uses it at a time.
    let processPaths: ProcessPathMemory
    
    /// - Parameters:
    ///   - eventClass: The lane's client.
    ///   - sensorID: The Sensor ID to stamp on the event.
    ///   - encoder: The lane's own encoder.
    ///   - processPaths: The lane's own process path memory, by default an empty one.
    init(eventClass: EventClass, sensorID: String, encoder: StreamingJSONEncoder,
         processPaths: ProcessPathMemory = ProcessPathMemory(capacity: ProcessPathMemory.laneCapacity)) {
        self.eventClass = eventClass
        self.sensorID = sensorID
        self.encoder = encoder
        self.processPaths = processPaths
    }
}


/// Turns one Endpoint Security message into the JSON a capture session emits.
///
/// Called on a lane's handler queue: serially within a lane, and concurrently across the lanes of a session (and
/// across sessions), so it must keep no shared mutable state of its own.
protocol EventSerializing {
    /// Serialize one message.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - lane: The lane's context.
    /// - Returns: The event's JSON, or `nil` if it couldn't be encoded.
    func serialize(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> Data?
}


/// Mac Monitor's serializer: builds a `Message` and encodes it as JSON, the one place a capture session pays the
/// per-event build and encode cost.
///
/// It also stamps the launched-by parent of the process an exec or fork creates (``LaunchedByParent``), from the
/// message's own fields: no lock and no IPC. A parent's path comes from the processes the lane's execs and forks named
/// before (``LaneContext/processPaths``), or else from one `proc_pidpath`, remembered for the next child.
struct MessageSerializer: EventSerializing {
    /// Signing IDs Apple forces into File Quarantine, read once rather than per event.
    private let forcedQuarantineSigningIDs: [String]
    /// This Mac's macOS version, read when the session starts rather than per event.
    private let macOSVersion: String
    /// Reads a live process's executable, for a launched-by parent the lane hasn't seen.
    private let processPath: (Int32, AuditToken?) -> String?
    
    /// - Parameters:
    ///   - forcedQuarantineSigningIDs: Signing IDs Apple forces into File Quarantine.
    ///   - macOSVersion: The macOS version to stamp on events.
    ///   - processPath: Reads a live process's executable from its pid (``ProcessPath/live``).
    init(forcedQuarantineSigningIDs: [String] = ProcessHelpers.forcedQuarantineSigningIDs,
         macOSVersion: String = Message.currentMacOSVersion(),
         processPath: @escaping (Int32, AuditToken?) -> String? = ProcessPath.live) {
        self.forcedQuarantineSigningIDs = forcedQuarantineSigningIDs
        self.macOSVersion = macOSVersion
        self.processPath = processPath
    }
    
    /// Build the message's `Message`, stamped with the lane's Sensor ID, this Mac's macOS version and, for an exec or
    /// fork, the created process's launched-by parent, and encode it.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - lane: The lane's context.
    /// - Returns: The JSON, or `nil` if the event couldn't be encoded.
    func serialize(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> Data? {
        var event = Message(from: message, sensorID: lane.sensorID, macOS: macOSVersion,
                            forcedQuarantineSigningIDs: forcedQuarantineSigningIDs)
        let paths = lane.processPaths
        event.resolveLaunchedByParent(by: .securityExtension) { pid, token in
            paths.path(of: pid, token, reading: processPath)
        }
        paths.remember(processesOf: event)
        return try? lane.encoder.encode(event)
    }
}
