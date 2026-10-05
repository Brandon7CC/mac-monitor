//
//  CaptureLane.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity
import os


// MARK: - Capture lane
/// One client of a ``CaptureSession``, and the work done for each of its messages on the client's handler queue.
///
/// Lanes keep no state in common: each has its own locks, encoder, process path memory, copy of the Sensor ID, and
/// drop counters. Building an event still takes locks the whole process shares, so lanes building events at once wait
/// on each other there: ``RandomUUIDBuffer/shared``'s for every model's `id`, ``CodeSigningCertificateCache/shared``'s,
/// and libinfo's user cache's behind `getpwuid`.
///
/// **Control:** whether to record, and the Sensor ID, are read under a lock of their own as each message is handled.
/// So turning recording on or off, or changing the Sensor ID, never waits for an event being built; one already being
/// built still goes out.
///
/// **Gate:** the gate's lock is held while a message is serialized and emitted. Once ``close()`` has marked the lane
/// closed and ``waitUntilIdle(until:)`` has taken the gate, the lane makes no Endpoint Security call (an event being
/// built can hold the message with `es_retain_message`) and emits nothing more: its client can be deleted. Building an
/// event has no time limit (an exec's script is read from disk, a signature checked with `trustd`), so the wait has a
/// deadline, after which the event being built is dropped and ``deleteClientOnceIdle(completion:)`` deletes the client
/// once it's done.
///
/// **Counters:** every message the client is handed is counted first, under a lock of its own, recording or not. So
/// sequence gaps are Endpoint Security's drops only, never messages ignored while stopped, and reading the counters
/// never waits for an event being built. Messages skipped because the lane isn't recording (and isn't closed) are
/// counted under the control lock, so once recording is turned on, every message skipped before it is counted.
final class CaptureLane {
    /// What the handler checks before it serializes a message, and before it emits the event.
    private struct Control {
        /// Serialize and emit messages?
        var isRecording = false
        /// Closed for good: the client is about to be deleted.
        var isClosed = false
        /// Closing gave up waiting for the event being built, which is dropped rather than emitted late.
        var isAbandoned = false
        /// The Sensor ID to stamp on events.
        var sensorID: String
        /// Messages skipped while open but not recording.
        var skipped: UInt64 = 0
        
        /// The Sensor ID to stamp on a message, while recording and open. A message turned away while open but not
        /// recording is counted as skipped.
        ///
        /// - Returns: The Sensor ID, or `nil` to skip the message.
        mutating func admit() -> String? {
            guard !isClosed else { return nil }
            guard isRecording else {
                skipped &+= 1
                return nil
            }
            return sensorID
        }
    }
    
    /// What the lane has seen of its client's messages.
    private struct Counters {
        /// Messages handed to the handler.
        var messages: UInt64 = 0
        /// Endpoint Security's sequence numbers, for drops.
        var sequences = ClientSequenceTracker()
        /// Messages that couldn't be serialized.
        var serializationFailures: UInt64 = 0
        /// The drops counted by the last ``CaptureLane/takeDropReport()``.
        var reported = DropReportMark()
    }
    
    /// The client this lane serves.
    let eventClass: EventClass
    /// The lane's client: set while the session starts, cleared once it's deleted. Only the session's queue touches it.
    private(set) var client: (any EndpointSecurityClient)?
    private let control: OSAllocatedUnfairLock<Control>
    /// Held while a message is serialized and emitted.
    private let gate = OSAllocatedUnfairLock()
    private let counters = OSAllocatedUnfairLock(uncheckedState: Counters())
    /// Only used under ``gate``.
    private let encoder = StreamingJSONEncoder()
    /// The executables of the processes the lane's execs and forks named. Only used under ``gate``.
    private let processPaths = ProcessPathMemory(capacity: ProcessPathMemory.laneCapacity)
    private let serializer: any EventSerializing
    private let emit: (CapturedEvent) -> Void
    
    /// A lane that isn't recording and has no client yet.
    ///
    /// - Parameters:
    ///   - eventClass: The client this lane serves.
    ///   - sensorID: The Sensor ID to stamp on events.
    ///   - serializer: Builds each event's JSON.
    ///   - emit: Receives each event, on the client's handler queue, under the lane's locks: it must not block or call
    ///     back into the session.
    init(_ eventClass: EventClass, sensorID: String, serializer: any EventSerializing,
         emit: @escaping (CapturedEvent) -> Void) {
        self.eventClass = eventClass
        self.serializer = serializer
        self.emit = emit
        control = OSAllocatedUnfairLock(initialState: Control(sensorID: sensorID))
    }
    
    /// The client's handler: count the message, then, while recording, serialize it and emit it.
    ///
    /// - Parameter message: The message. Only valid during the call.
    func handle(_ message: UnsafePointer<es_message_t>) {
        counters.withLockUnchecked { counters in
            counters.messages &+= 1
            counters.sequences.observe(message)
        }
        gate.withLockUnchecked {
            guard let sensorID = control.withLock({ $0.admit() }) else { return }
            let lane = LaneContext(eventClass: eventClass, sensorID: sensorID, encoder: encoder,
                                   processPaths: processPaths)
            guard let json = serializer.serialize(message, in: lane) else {
                counters.withLockUnchecked { $0.serializationFailures &+= 1 }
                return
            }
            let event = CapturedEvent(json: json, eventClass: eventClass)
            /// Under the control lock, so an event is never emitted once closing has given up on it.
            control.withLockUnchecked { state in
                if !state.isAbandoned { emit(event) }
            }
        }
    }
    
    /// Does this lane's client serve an event?
    ///
    /// - Parameter event: An event type.
    /// - Returns: `true` if ``EventClassTable`` gives the event this lane's class.
    func serves(_ event: es_event_type_t) -> Bool {
        EventClassTable.eventClass(of: event) == eventClass
    }
    
    /// Give the lane its client. Call once, on the session's queue.
    ///
    /// - Parameter client: The client whose handler is ``handle(_:)``.
    func attach(_ client: any EndpointSecurityClient) {
        self.client = client
    }
    
    /// Start or stop serializing messages. Has no effect once the lane is closed.
    ///
    /// - Parameter recording: `true` to serialize and emit messages.
    func setRecording(_ recording: Bool) {
        control.withLock { $0.isRecording = recording }
    }
    
    /// Stamp a new Sensor ID on events from now on.
    ///
    /// - Parameter sensorID: The Sensor ID.
    func setSensorID(_ sensorID: String) {
        control.withLock { $0.sensorID = sensorID }
    }
    
    /// Stop for good, without waiting: messages still on their way are counted and ignored. An event already being
    /// built still goes out, unless ``waitUntilIdle(until:)`` gives up on it.
    func close() {
        control.withLock { $0.isClosed = true }
    }
    
    /// Wait, after ``close()``, until no event is being built, or until a deadline.
    ///
    /// - Parameter deadline: When to give up.
    /// - Returns: `true` once no event is being built: from then on the lane emits nothing and makes no Endpoint
    ///   Security call. `false` if one still was at the deadline: that event is dropped when it's done.
    func waitUntilIdle(until deadline: DispatchTime) -> Bool {
        while gate.withLockIfAvailable({ true }) == nil {
            guard DispatchTime.now() < deadline else {
                control.withLock { $0.isAbandoned = true }
                return false
            }
            usleep(1_000)
        }
        return true
    }
    
    /// Messages skipped while the lane was open but not recording, over its lifetime.
    var skippedMessages: UInt64 {
        control.withLock { $0.skipped }
    }
    
    /// The lane's lifetime counters.
    ///
    /// - Parameter subscribedEvents: How many events the lane's client is subscribed to.
    /// - Returns: The counters.
    func statistics(subscribedEvents: Int) -> CaptureLaneStatistics {
        counters.withLockUnchecked { counters in
            CaptureLaneStatistics(eventClass: eventClass, subscribedEvents: subscribedEvents,
                                  messages: counters.messages, dropped: counters.sequences.global.dropped,
                                  gaps: counters.sequences.global.gaps,
                                  regressions: counters.sequences.global.regressions,
                                  droppedByType: counters.sequences.droppedByType().byEventTypeName(),
                                  serializationFailures: counters.serializationFailures)
        }
    }
    
    /// The messages Endpoint Security dropped since the last call.
    ///
    /// - Returns: The drops, or `nil` if there were none.
    func takeDropReport() -> CaptureDropReport? {
        counters.withLockUnchecked { counters in
            counters.reported.takeReport(of: eventClass, from: counters.sequences)
        }
    }
    
    /// Delete the lane's client. Call on the session's queue, once ``waitUntilIdle(until:)`` returned `true`.
    ///
    /// - Returns: `false` if Endpoint Security leaked the client's resources.
    @discardableResult
    func deleteClient() -> Bool {
        defer { client = nil }
        return client?.delete() ?? true
    }
    
    /// Hand the lane's client to a background queue that deletes it once no event is being built. Call on the
    /// session's queue, once ``waitUntilIdle(until:)`` gave up, so the session's queue never waits on a slow event.
    ///
    /// Nothing else calls the client by then: the session is stopped, and the lane is closed.
    ///
    /// - Parameter completion: Called on that queue with whether Endpoint Security freed the client's resources.
    func deleteClientOnceIdle(completion: @escaping (Bool) -> Void) {
        guard let client else { return completion(true) }
        self.client = nil
        DispatchQueue.global(qos: .utility).async { [gate] in
            gate.withLock {}
            completion(client.delete())
        }
    }
}
