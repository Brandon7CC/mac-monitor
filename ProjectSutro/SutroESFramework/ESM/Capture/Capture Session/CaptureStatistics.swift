//
//  CaptureStatistics.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Lane statistics
/// One capture client's lifetime counters.
///
/// Each client has its own `global_seq_num` and `seq_num` streams, so drops are counted per client: a consumer
/// checking a live trace for gaps groups its events by ``EventClassTable/eventClass(of:)``.
public struct CaptureLaneStatistics: Codable, Equatable, Sendable {
    /// The client.
    public let eventClass: EventClass
    /// How many events it's subscribed to.
    public let subscribedEvents: Int
    /// Messages Endpoint Security handed to it, recording or not.
    public let messages: UInt64
    /// Messages Endpoint Security dropped before handing them over (`global_seq_num` gaps).
    public let dropped: UInt64
    /// How many times at least one message was dropped.
    public let gaps: UInt64
    /// How many times `global_seq_num` repeated or went backwards, which Endpoint Security should never do: if it did,
    /// ``dropped`` and ``gaps`` can't be trusted.
    public let regressions: UInt64
    /// Dropped messages by `ES_EVENT_TYPE_*` name (`seq_num` gaps), for the types that lost any.
    public let droppedByType: [String: UInt64]
    /// Messages that couldn't be serialized while recording.
    public let serializationFailures: UInt64
}


// MARK: - Drop reports
/// The messages Endpoint Security dropped for one capture client since the last report.
public struct CaptureDropReport: Equatable, Sendable {
    /// The client.
    public let eventClass: EventClass
    /// Messages dropped since the last report (`global_seq_num` gaps).
    public let dropped: UInt64
    /// Of those, the ones whose type is known (`seq_num` gaps), by `ES_EVENT_TYPE_*` name.
    public let droppedByType: [String: UInt64]
    
    /// The event types dropped, most first, such as "ES_EVENT_TYPE_NOTIFY_OPEN 100, ES_EVENT_TYPE_NOTIFY_CLOSE 20".
    public var typeSummary: String {
        droppedByType.sorted { ($1.value, $0.key) < ($0.value, $1.key) }
            .map { "\($0.key) \($0.value)" }
            .joined(separator: ", ")
    }
}


// MARK: - Naming event types
extension Dictionary where Key == Int, Value == UInt64 {
    /// Counts by `es_event_type_t` raw value, keyed by `ES_EVENT_TYPE_*` name instead.
    ///
    /// - Returns: The counts by name. Types Mac Monitor doesn't name are added up under `ES_EVENT_TYPE_LAST`.
    func byEventTypeName() -> [String: UInt64] {
        Dictionary<String, UInt64>(map { type, count in
            (eventTypeToString(from: es_event_type_t(rawValue: UInt32(type))), count)
        }, uniquingKeysWith: +)
    }
}
