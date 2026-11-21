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
    /// The types of the files the lane's mmaps mapped (``FileTypeMemory``). The lane's own: only one thread uses it at
    /// a time.
    var fileTypes = FileTypeMemory()
    /// Does the lane hold app execs (``LaunchServicesHold``)?
    var holdsForLaunchServices = false
    /// The indicators the message was admitted with, which its event is stamped with. `nil` evaluates nothing, and
    /// the event carries no verdicts.
    var indicators: CompiledIndicators? = nil
    /// The session's chains for their sequences (``SessionChains``), or `nil` for the set's own.
    var chains: SessionChains? = nil
    /// The lane's values for evaluating them. The lane's own: only one thread uses it at a time.
    var indicatorState = LaneIndicators()
    /// The lineage table the session keeps told (``LineageMonitor``): execs and forks are stamped with their
    /// ancestors' keys from it, and indicators read an event's ancestors from it. `nil` when lineage isn't tracked.
    var lineage: ProcessLineage? = nil
    /// The snapshots the lane owes for ancestors its execs and forks name (``ProcessSnapshot``). `nil` when lineage
    /// isn't tracked.
    var snapshots: LaneSnapshots? = nil
}


/// A serialized message
enum SerializedEvent {
    case json(Data)
    /// An app exec to hold, not encoded yet, and the sequence steps its stamp deferred
    case held(Message, steps: ContiguousArray<Int32> = [])
    /// An event of a lane that holds app execs which matched sequence steps, not encoded yet: its steps advance as
    /// the hold sends it, in the lane's order (``LaunchServicesHold``)
    case stamped(Message, steps: ContiguousArray<Int32>)
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
/// before (``LaneContext/processPaths``), or else from one `proc_pidpath`, remembered for the next child. And it names
/// the type of an mmap's file, or a modified close's, from the file's first bytes
/// (``Message/identifyFileType(of:in:)``). Last, it stamps the indicators the event matches, from the lane's set
/// (``LaneContext/indicators``), so an exec held for Launch Services carries its verdicts while it waits.
struct MessageSerializer: EventSerializing {
    /// This Mac's macOS version, read when the session starts rather than per event.
    private let macOSVersion: String
    /// This Mac's System Integrity Protection status, read when the session starts: it changes only at a restart.
    private let sipStatus: SIPStatus?
    /// This boot session's identifier, read when the session starts: it changes only at a restart.
    private let bootSession: String?
    /// Reads a live process's executable, for a launched-by parent the lane hasn't seen.
    private let processPath: (Int32, AuditToken?) -> String?
    
    /// Also reads the signing IDs Apple forces into File Quarantine (``ProcessHelpers/forcedQuarantineSigningIDs``)
    /// now, when the session starts, rather than on the first event that checks them.
    ///
    /// - Parameters:
    ///   - macOSVersion: The macOS version to stamp on events.
    ///   - sipStatus: The System Integrity Protection status to stamp on events.
    ///   - bootSession: The boot session's identifier to stamp on events (``BootSession``).
    ///   - processPath: Reads a live process's executable from its pid (``ProcessPath/live``).
    init(macOSVersion: String = Message.currentMacOSVersion(), sipStatus: SIPStatus? = SIPStatus.current,
         bootSession: String? = BootSession.current,
         processPath: @escaping (Int32, AuditToken?) -> String? = ProcessPath.live) {
        _ = ProcessHelpers.forcedQuarantineSigningIDs
        self.macOSVersion = macOSVersion
        self.sipStatus = sipStatus
        self.bootSession = bootSession
        self.processPath = processPath
    }
    
    /// Build and encode the message, unless it's an app exec to hold, or an event of a lane that holds them which
    /// matched sequence steps.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - lane: The lane's context.
    /// - Returns: The JSON, the event for the hold, or `nil` if the event couldn't be encoded.
    func serializeEvent(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> SerializedEvent? {
        let (event, steps) = build(message, in: lane)
        if lane.holdsForLaunchServices && LaunchServicesHold.holds(event) { return .held(event, steps: steps) }
        if !steps.isEmpty { return .stamped(event, steps: steps) }
        return (try? lane.encoder.encode(event)).map(SerializedEvent.json)
    }
    
    /// Build the `Message` with the Sensor ID, macOS version, SIP status, for execs and forks the launched-by parent
    /// and the ancestors' keys, for mmaps and modified closes the file's type, and the indicators it matches.
    ///
    /// A lane that holds app execs defers every event's sequence steps to the hold, which advances them as it sends
    /// the event.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - lane: The lane's context.
    /// - Returns: The event, and the sequence steps it matched, left for the hold.
    private func build(_ message: UnsafePointer<es_message_t>,
                       in lane: LaneContext) -> (Message, ContiguousArray<Int32>) {
        var event = Message(from: message, sensorID: lane.sensorID, macOS: macOSVersion, sipStatus: sipStatus,
                            bootSession: bootSession)
        let paths = lane.processPaths
        event.resolveLaunchedByParent(by: .securityExtension) { pid, token in
            paths.path(of: pid, token, reading: processPath)
        }
        paths.remember(processesOf: event)
        if let lineage = lane.lineage {
            lineage.note(event, at: ProcessInfo.processInfo.systemUptime)
            let ancestors = event.stampAncestorKeys(from: lineage)
            lane.snapshots?.describe(event, naming: ancestors, from: lineage)
        }
        event.identifyFileType(of: message, in: lane.fileTypes)
        let steps = lane.indicatorState.stamp(&event, with: lane.indicators, chains: lane.chains,
                                              deferringSteps: lane.holdsForLaunchServices, lineage: lane.lineage)
        return (event, steps)
    }
}
