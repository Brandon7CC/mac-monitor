//
//  SequenceGapCounter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Sequence gaps
/// Counts the messages Endpoint Security dropped from one sequence-number stream.
///
/// From `ESMessage.h`: when nothing is dropped a sequence number goes up by 1 with every message, and otherwise the
/// difference between the last number seen plus 1 and the number received is how many messages were dropped. The first
/// message only sets the baseline, so drops before it can't be seen.
struct SequenceGapCounter: Equatable {
    /// Messages observed.
    private(set) var observed: UInt64 = 0
    /// The last sequence number observed.
    private(set) var last: UInt64?
    /// Messages missing between observed ones.
    private(set) var dropped: UInt64 = 0
    /// How many times at least one message was missing.
    private(set) var gaps: UInt64 = 0
    /// How many times the number went backwards or repeated, which Endpoint Security should never do.
    private(set) var regressions: UInt64 = 0
    
    /// Account for the next message's sequence number.
    ///
    /// - Parameter sequence: The message's `seq_num` or `global_seq_num`.
    mutating func observe(_ sequence: UInt64) {
        observed &+= 1
        defer { last = sequence }
        guard let last, sequence != last &+ 1 else { return }
        if sequence > last {
            gaps &+= 1
            dropped &+= sequence - last - 1
        } else {
            regressions &+= 1
        }
    }
}


// MARK: - Client sequences
/// Drop accounting for one Endpoint Security client.
///
/// Per `ESMessage.h`, `global_seq_num` is per client (one more for every message the client is sent) and `seq_num` is
/// per client and per event type. Both are tracked: the global stream catches every drop that is followed by a later
/// message, and the per-type streams say which event types were lost. A drop of the last messages of a type that never
/// comes again shows up only in the global count. Muted messages are never sent, so they're never counted as drops.
struct ClientSequenceTracker {
    /// `global_seq_num` (message version 4 and later).
    private(set) var global = SequenceGapCounter()
    /// `seq_num` per event type, by `es_event_type_t` raw value.
    private var byType: [SequenceGapCounter]
    
    /// - Parameter eventTypeCount: Room for event types up front. It grows on demand.
    init(eventTypeCount: Int = Int(ES_EVENT_TYPE_LAST.rawValue)) {
        byType = Array(repeating: SequenceGapCounter(), count: eventTypeCount)
    }
    
    /// Account for one message, reading only the numbers its version has.
    ///
    /// - Parameter message: The message. Only read during the call.
    mutating func observe(_ message: UnsafePointer<es_message_t>) {
        let version = message.pointee.version
        observe(eventType: Int(message.pointee.event_type.rawValue),
                sequence: version >= 2 ? message.pointee.seq_num : nil,
                globalSequence: version >= 4 ? message.pointee.global_seq_num : nil)
    }
    
    /// Account for one message's numbers.
    ///
    /// - Parameters:
    ///   - eventType: The message's `event_type` raw value.
    ///   - sequence: Its `seq_num`, or `nil` before message version 2.
    ///   - globalSequence: Its `global_seq_num`, or `nil` before message version 4.
    mutating func observe(eventType: Int, sequence: UInt64?, globalSequence: UInt64?) {
        if let globalSequence { global.observe(globalSequence) }
        guard let sequence else { return }
        if eventType >= byType.count {
            byType += Array(repeating: SequenceGapCounter(), count: eventType - byType.count + 1)
        }
        byType[eventType].observe(sequence)
    }
    
    /// Messages of one event type that carried a `seq_num`.
    ///
    /// - Parameter eventType: An `es_event_type_t` raw value.
    /// - Returns: How many were observed.
    func observed(eventType: Int) -> UInt64 {
        eventType < byType.count ? byType[eventType].observed : 0
    }
    
    /// Dropped messages for each event type that lost any.
    ///
    /// - Returns: Drop counts by `es_event_type_t` raw value.
    func droppedByType() -> [Int: UInt64] {
        var drops: [Int: UInt64] = [:]
        for (eventType, counter) in byType.enumerated() where counter.dropped > 0 {
            drops[eventType] = counter.dropped
        }
        return drops
    }
}


// MARK: - Drop reports
/// What a client's sequence tracker had counted when its drops were last reported, so each report holds only the
/// drops since.
struct DropReportMark {
    /// `global_seq_num` drops at the last report.
    private var dropped: UInt64 = 0
    /// `seq_num` drops by event type at the last report.
    private var byType: [Int: UInt64] = [:]
    
    /// The drops a tracker counted since the last report, which this then marks as reported.
    ///
    /// - Parameters:
    ///   - eventClass: The tracker's client.
    ///   - sequences: The tracker.
    /// - Returns: The new drops, or `nil` if there were none.
    mutating func takeReport(of eventClass: EventClass, from sequences: ClientSequenceTracker) -> CaptureDropReport? {
        let dropped = sequences.global.dropped
        let byType = sequences.droppedByType()
        guard dropped != self.dropped || byType != self.byType else { return nil }
        let newByType = byType.reduce(into: [Int: UInt64]()) { new, entry in
            let reported = self.byType[entry.key, default: 0]
            if entry.value > reported { new[entry.key] = entry.value - reported }
        }
        let report = CaptureDropReport(eventClass: eventClass, dropped: dropped - self.dropped,
                                       droppedByType: newByType.byEventTypeName())
        self.dropped = dropped
        self.byType = byType
        return report
    }
}
