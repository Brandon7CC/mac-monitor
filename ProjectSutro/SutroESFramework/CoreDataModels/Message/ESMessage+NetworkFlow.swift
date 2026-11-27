//
//  ESMessage+NetworkFlow.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import EndpointSecurity


// MARK: - Network flows
extension ESMessage {
    /// Is it a network flow (``MacMonitorEvent``), whose record is Mac Monitor's own?
    public var isNetworkFlow: Bool { Self.isNetworkFlow(event_type) }

    /// - Parameter eventType: A stored event's `event_type`.
    /// - Returns: Is it a network flow's (``MacMonitorEvent``)?
    public static func isNetworkFlow(_ eventType: Int32) -> Bool {
        MacMonitorEvent(es_event_type_t(rawValue: UInt32(truncatingIfNeeded: eventType))) != nil
    }

    /// Encode a network flow as its record: Mac Monitor's own, with no `event_type`, `es_event_type`, version,
    /// sequence numbers, thread or action, and its process as `flow_process` (``FlowProcessRecord``). The same keys
    /// as the indicator engine reads (``NetworkRecordView``).
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The encoder's error.
    func encodeNetworkFlow(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(TelemetrySchema.version, forKey: .telemetry_version)
        if let indicators = RecordIndicators.current, let hits = recordedIndicators(with: indicators) {
            try container.encode(hits, forKey: .indicators)
            try container.encodeIfPresent(recordedUndetermined, forKey: .indicators_undetermined)
        }
        try container.encode(time, forKey: .time)
        try container.encode(mach_time, forKey: .mach_time)
        try container.encode(macOS, forKey: .macOS)
        try container.encode(sip_status, forKey: .sip_status)
        try container.encode(boot_session_uuid, forKey: .boot_session_uuid)
        try container.encode(sensor_id, forKey: .sensor_id)
        try container.encode(FlowProcessRecord(process), forKey: .process)
        try container.encodeIfPresent(event, forKey: .event)
        try container.encode(context, forKey: .context)
        try container.encode(target_path, forKey: .target_path)
    }
}
