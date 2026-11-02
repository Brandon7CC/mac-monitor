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
    var processPaths = ProcessPathMemory(capacity: ProcessPathMemory.laneCapacity)
    /// Does the lane hold app execs (``LaunchServicesHold``)?
    var holdsForLaunchServices = false
}


/// A serialized message
enum SerializedEvent {
    case json(Data)
    /// An app exec to hold, not encoded yet
    case held(Message)
}


/// Turns one Endpoint Security message into the JSON a capture session emits.
///
/// Called on a lane's handler queue: serially within a lane, and concurrently across the lanes of a session (and
/// across sessions), so it must keep no shared mutable state of its own.
protocol EventSerializing {
    /// Serialize one message, or hand back an exec for the lane to hold.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - lane: The lane's context.
    /// - Returns: The event, or `nil` if it couldn't be encoded.
    func serializeEvent(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> SerializedEvent?
}


/// Mac Monitor's serializer: builds a `Message` and encodes it as JSON, the one place a capture session pays the
/// per-event build and encode cost.
///
/// It also stamps the launched-by parent of the process an exec or fork creates (``LaunchedByParent``), from the
/// message's own fields: no lock and no IPC. A parent's path comes from the processes the lane's execs and forks named
/// before (``LaneContext/processPaths``), or else from one `proc_pidpath`, remembered for the next child.
struct MessageSerializer: EventSerializing {
    /// This Mac's macOS version, read when the session starts rather than per event.
    private let macOSVersion: String
    /// This Mac's System Integrity Protection status, read when the session starts: it changes only at a restart.
    private let sipStatus: SIPStatus?
    /// Reads a live process's executable, for a launched-by parent the lane hasn't seen.
    private let processPath: (Int32, AuditToken?) -> String?
    
    /// Also reads the signing IDs Apple forces into File Quarantine (``ProcessHelpers/forcedQuarantineSigningIDs``)
    /// now, when the session starts, rather than on the first event that checks them.
    ///
    /// - Parameters:
    ///   - macOSVersion: The macOS version to stamp on events.
    ///   - sipStatus: The System Integrity Protection status to stamp on events.
    ///   - processPath: Reads a live process's executable from its pid (``ProcessPath/live``).
    init(macOSVersion: String = Message.currentMacOSVersion(), sipStatus: SIPStatus? = SIPStatus.current,
         processPath: @escaping (Int32, AuditToken?) -> String? = ProcessPath.live) {
        _ = ProcessHelpers.forcedQuarantineSigningIDs
        self.macOSVersion = macOSVersion
        self.sipStatus = sipStatus
        self.processPath = processPath
    }
    
    /// Build and encode the message, unless it's an app exec to hold.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - lane: The lane's context.
    /// - Returns: The JSON, the exec to hold, or `nil` if the event couldn't be encoded.
    func serializeEvent(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> SerializedEvent? {
        let event = build(message, in: lane)
        if lane.holdsForLaunchServices && LaunchServicesHold.holds(event) { return .held(event) }
        return (try? lane.encoder.encode(event)).map(SerializedEvent.json)
    }
    
    /// Build the `Message` with the Sensor ID, macOS version, SIP status and, for execs and forks, the launched-by
    /// parent.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - lane: The lane's context.
    /// - Returns: The event.
    private func build(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> Message {
        var event = Message(from: message, sensorID: lane.sensorID, macOS: macOSVersion, sipStatus: sipStatus)
        let paths = lane.processPaths
        event.resolveLaunchedByParent(by: .securityExtension) { pid, token in
            paths.path(of: pid, token, reading: processPath)
        }
        paths.remember(processesOf: event)
        return event
    }
}
