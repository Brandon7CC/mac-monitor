//
//  StreamDropMeter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Drop meter
/// Counts the events a `macmonitor` stream lost, from the sequence numbers of the events it received.
///
/// A stream's capture session has one Endpoint Security client per ``EventClass``, and `global_seq_num` is per client
/// (`ESMessage.h`), so the meter keeps one tracker per class and files each event under its client
/// (``EventClassTable/eventClass(of:)``): interleaved classes never look like gaps. Each tracker also follows `seq_num`
/// per event type, which says which types were lost.
///
/// A gap is a real loss: Endpoint Security dropped the message, or the stream was behind (its buffer was full or
/// capture was paused). Muted messages are never sent, so they never count, and the pipeline's own events are
/// observed before they're suppressed. Not thread-safe.
public final class StreamDropMeter {
    /// Each client's sequence numbers so far.
    private var trackers: [EventClass: ClientSequenceTracker] = [:]
    /// What each client's last report held.
    private var marks: [EventClass: DropReportMark] = [:]
    
    /// A meter that has seen nothing.
    public init() {}
    
    /// Account for one event's sequence numbers.
    ///
    /// - Parameter header: The event's header.
    public func observe(_ header: EventHeader) {
        /// A type outside the range Endpoint Security uses only counts toward the global sequence.
        let isTyped = (0..<Self.eventTypeLimit).contains(header.eventType)
        let type = es_event_type_t(rawValue: UInt32(truncatingIfNeeded: header.eventType))
        trackers[EventClassTable.eventClass(of: type), default: ClientSequenceTracker()].observe(
            eventType: isTyped ? header.eventType : 0,
            sequence: isTyped ? header.sequence.flatMap(UInt64.init(exactly:)) : nil,
            globalSequence: header.globalSequence.flatMap(UInt64.init(exactly:)))
    }
    
    /// One past the largest `event_type` tracked per type: room for many more than Endpoint Security defines.
    static let eventTypeLimit = 1_024
    
    /// Every event lost so far (`global_seq_num` gaps), over every client.
    public var dropped: UInt64 {
        trackers.values.reduce(0) { $0 + $1.global.dropped }
    }
    
    /// How many times a `global_seq_num` repeated or went backwards, which makes ``dropped`` untrustworthy.
    public var regressions: UInt64 {
        trackers.values.reduce(0) { $0 + $1.global.regressions }
    }
    
    /// The events lost since the last call, for each client that lost any.
    ///
    /// - Returns: One report per client with new drops, in ``EventClass/allCases`` order.
    public func takeReport() -> [CaptureDropReport] {
        EventClass.allCases.compactMap { eventClass in
            guard let tracker = trackers[eventClass] else { return nil }
            return marks[eventClass, default: DropReportMark()].takeReport(of: eventClass, from: tracker)
        }
    }
}
