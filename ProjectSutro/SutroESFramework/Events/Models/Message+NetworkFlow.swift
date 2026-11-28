//
//  Message+NetworkFlow.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import EndpointSecurity


// MARK: - Network flows as messages
extension Message {
    /// Model a network flow, with Mac Monitor's enrichment, as a session that records flows does.
    ///
    /// A flow's `Message` keeps its event's number as `event_type` and its name as `es_event_type`, which the wire, the
    /// event store and the app read. It has no version, sequence numbers, thread or action. Its record writes none of
    /// these (``NetworkRecordView``). `time`, `mach_time` and `message_darwin_time` are all the record's own time:
    /// when the flow was seen to connect, or to close.
    ///
    /// - Parameters:
    ///   - record: The flow, as the client handed it over.
    ///   - keepingURLPath: Keep the URL's path? Without it the URL ends at the host and port.
    ///   - sensorID: The Sensor ID to stamp on the event.
    ///   - macOS: The macOS version to stamp on the event.
    ///   - sipStatus: System Integrity Protection's status to stamp on the event.
    ///   - bootSession: The boot session's identifier to stamp on the event.
    init(flow record: FlowRecord, keepingURLPath: Bool, sensorID: String = "SENSOR-ID-NOT-SET",
         macOS: String = Message.currentMacOSVersion(), sipStatus: SIPStatus? = SIPStatus.current,
         bootSession: String? = BootSession.current) {
        version = 0
        schema_version = 0
        let wall = ESLogger.wallTime(nanoseconds: record.time.wall)
        time = ESLogger.time(wall)
        mach_time = record.time.machTime
        message_darwin_time = ProcessHelpers.timespecToTimestamp(timespec: wall)
        sensor_id = sensorID
        self.macOS = macOS
        sip_status = sipStatus?.rawValue
        boot_session_uuid = bootSession
        process = Process(flow: record.process)
        let flow = NetworkFlowEvent(record, keepingURLPath: keepingURLPath)
        event = record.kind == .opened ? .new_flow(flow) : .flow_closed(flow)
        event_type = 0
        action_type = 0
        action = ActionResultWrapper()
        enrich()
        deriveProcessAges()
    }

    /// Name a Mac Monitor event's type from its payload: its number as `event_type`, its name as `es_event_type`,
    /// and a notification's action type. A network record carries none of them, so a flow read back from a trace is
    /// named this way.
    mutating func nameMacMonitorEvent() {
        guard let named = event.macMonitorEvent else { return }
        event_type = Int(named.rawValue)
        es_event_type = named.name
        action_type = Int(ES_ACTION_TYPE_NOTIFY.rawValue)
        action_type_string = "ES_ACTION_TYPE_NOTIFY"
    }
}


// MARK: - A network flow's record
/// A network flow's `Message` with exactly its record's keys: Mac Monitor's own, with no `event_type`,
/// `es_event_type`, version, sequence numbers, thread or action, and its process as `flow_process`
/// (``FlowProcessRecord``). The indicator engine reads a flow's record fields through it, so a rule sees in the
/// Security Extension what the record has. The indicators aren't written: they come once the event is evaluated.
///
/// The event's payload is under `_0`, as the `Message` encodes it, which the engine's walk passes through.
enum NetworkRecordView {
    /// The record's keys.
    private enum CodingKeys: String, CodingKey {
        case telemetry_version, time, mach_time, macOS, sip_status, boot_session_uuid, sensor_id, process, event
        case context, target_path
    }

    /// Encode a flow's `Message` as its record.
    ///
    /// - Parameters:
    ///   - message: The flow's message, borrowed.
    ///   - encoder: The encoder.
    /// - Throws: The encoder's error.
    static func encode(_ message: borrowing Message, to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(TelemetrySchema.version, forKey: .telemetry_version)
        try container.encode(message.time, forKey: .time)
        try container.encode(message.mach_time, forKey: .mach_time)
        try container.encode(message.macOS, forKey: .macOS)
        try container.encode(message.sip_status, forKey: .sip_status)
        try container.encode(message.boot_session_uuid, forKey: .boot_session_uuid)
        try container.encode(message.sensor_id, forKey: .sensor_id)
        try container.encode(FlowProcessRecord(message.process), forKey: .process)
        try container.encode(message.event, forKey: .event)
        try container.encode(message.context ?? MessageValues.notSupported, forKey: .context)
        try container.encode(message.target_path ?? MessageValues.notSupported, forKey: .target_path)
    }
}
