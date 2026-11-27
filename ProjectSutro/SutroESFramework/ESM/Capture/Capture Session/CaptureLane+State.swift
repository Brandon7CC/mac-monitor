//
//  CaptureLane+State.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/27/26.
//

import Foundation
import EndpointSecurity


// MARK: - A lane's state
/// What a ``CaptureLane`` keeps under its locks: the control its handler checks, what an admitted message is built
/// with, and its counters.
extension CaptureLane {
    /// What the handler checks before it serializes a message, and before it emits the event.
    struct Control {
        /// Serialize and emit messages?
        var isRecording = false
        /// Closed for good: the client is about to be deleted.
        var isClosed = false
        /// Closing gave up waiting for the event being built, which is dropped rather than emitted late.
        var isAbandoned = false
        /// The Sensor ID to stamp on events.
        var sensorID: String
        /// The indicators to stamp events with, or `nil` for none.
        var indicators: CompiledIndicators?
        /// The session's chains for their sequences, or `nil` for the set's own.
        var chains: SessionChains?
        /// Scan written files and the scripts execs run, on a lane that has the scanner?
        var scansWrittenFiles = false
        /// Messages skipped while open but not recording.
        var skipped: UInt64 = 0
        /// Each event type's field filter, by its raw value (``FieldFilter/table(_:)``).
        var fieldFilters: ContiguousArray<FieldFilter?>
        /// Messages a field filter left out while open, by event type raw value. Allocated once.
        var fieldFiltered = ContiguousArray<UInt64>(repeating: 0, count: Int(ES_EVENT_TYPE_LAST.rawValue))
        
        /// What to build a message with, while open, admitted by its type's field filter, and recording. A message its
        /// filter turns away is counted as left out, and one turned away while not recording as skipped.
        ///
        /// - Parameter message: The message. Only read during the call.
        /// - Returns: The Sensor ID and indicators, or `nil` to skip the message.
        mutating func admit(_ message: UnsafePointer<es_message_t>) -> Admission? {
            guard !isClosed else { return nil }
            let type = Int(message.pointee.event_type.rawValue)
            if type < fieldFilters.count, let filter = fieldFilters[type], !filter.admits(message) {
                /// `type` is below the table's size, which is at most `ES_EVENT_TYPE_LAST`.
                fieldFiltered[type] &+= 1
                return nil
            }
            guard isRecording else {
                skipped &+= 1
                return nil
            }
            return Admission(sensorID: sensorID, indicators: indicators, chains: chains,
                             scansWrittenFiles: scansWrittenFiles)
        }
    }
    
    /// What a message admitted is built with: read together, under the control lock.
    struct Admission {
        /// The Sensor ID to stamp on its event.
        let sensorID: String
        /// The indicators to stamp its event with: one reference, retained for the event.
        let indicators: CompiledIndicators?
        /// The session's chains for their sequences.
        let chains: SessionChains?
        /// Scan the written file or the script its event names?
        let scansWrittenFiles: Bool
    }
    
    /// What the lane has seen of its client's messages.
    struct Counters {
        /// Messages handed to the handler.
        var messages: UInt64 = 0
        /// Endpoint Security's sequence numbers, for drops.
        var sequences = ClientSequenceTracker()
        /// Messages that couldn't be serialized.
        var serializationFailures: UInt64 = 0
        /// The indicator counts the lane last took from its ``LaneIndicators``.
        var indicators = IndicatorCounts()
        /// The drops counted by the last ``CaptureLane/takeDropReport()``.
        var reported = DropReportMark()
    }
}
