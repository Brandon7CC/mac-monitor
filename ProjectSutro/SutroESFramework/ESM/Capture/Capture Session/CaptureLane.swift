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
/// **Control:** whether to record, the Sensor ID, and the indicators are read under a lock of their own as each
/// message is handled. So turning recording on or off, or changing the Sensor ID or the indicators, never waits for an
/// event being built. One already being built still goes out, judged by the indicators it was admitted with.
///
/// **Gate:** the gate's lock is held while a message is serialized and emitted. Once ``close()`` has marked the lane
/// closed and ``waitUntilIdle(until:)`` has taken the gate, the lane makes no Endpoint Security call (an event being
/// built can hold the message with `es_retain_message`) and emits nothing more: its client can be deleted. Building an
/// event has no time limit (an exec's script is read from disk, a signature checked with `trustd`), so the wait has a
/// deadline, after which the event being built is dropped and ``deleteClient(by:)`` deletes the client once it's
/// done.
///
/// **Counters:** every message the client is handed is counted first, under a lock of its own, recording or not. So
/// sequence gaps are Endpoint Security's drops only, never messages ignored while stopped, and reading the counters
/// never waits for an event being built. Messages skipped because the lane isn't recording (and isn't closed) are
/// counted under the control lock, so once recording is turned on, every message skipped before it is counted.
///
/// **Field filters:** a message its type's ``FieldFilter`` turns away is left out: counted under the control lock,
/// after sequence accounting (so it's never a drop) and before the recording check (so it's never skipped). It never
/// reaches the serializer or the ``LaunchServicesHold``.
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
        /// The indicators to stamp events with, or `nil` for none.
        var indicators: CompiledIndicators?
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
            return Admission(sensorID: sensorID, indicators: indicators)
        }
    }
    
    /// What a message admitted is built with: read together, under the control lock.
    private struct Admission {
        /// The Sensor ID to stamp on its event.
        let sensorID: String
        /// The indicators to stamp its event with: one reference, retained for the event.
        let indicators: CompiledIndicators?
    }
    
    /// What the lane has seen of its client's messages.
    private struct Counters {
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
    
    /// The client this lane serves.
    let eventClass: EventClass
    /// Names the lane's session in the log.
    let label: String
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
    /// The types of the files the lane's mmaps mapped. Only used under ``gate``.
    private let fileTypes = FileTypeMemory()
    /// The values the lane's events are evaluated with. Only used under ``gate``.
    private let indicatorState = LaneIndicators()
    private let serializer: any EventSerializing
    private let emit: (CapturedEvent) -> Void
    /// Only the exec lane has one
    private let hold: LaunchServicesHold?
    
    /// A lane that isn't recording and has no client yet.
    ///
    /// - Parameters:
    ///   - eventClass: The client this lane serves.
    ///   - label: Names the lane's session in the log.
    ///   - sensorID: The Sensor ID to stamp on events.
    ///   - serializer: Builds each event's JSON.
    ///   - fieldFilters: Each event type's field filter (``FieldFilter/table(_:)``), in place before any message.
    ///   - indicators: The indicators to stamp events with, in place before any message. `nil` stamps none.
    ///   - launchServices: Lets the exec lane hold app execs. `nil` holds nothing.
    ///   - emit: Receives each event in order, under the lane's locks. It must not block.
    init(_ eventClass: EventClass, label: String, sensorID: String, serializer: any EventSerializing,
         fieldFilters: ContiguousArray<FieldFilter?>, indicators: CompiledIndicators? = nil,
         launchServices: LaunchServicesReading? = nil, emit: @escaping (CapturedEvent) -> Void) {
        self.eventClass = eventClass
        self.label = label
        self.serializer = serializer
        self.emit = emit
        control = OSAllocatedUnfairLock(initialState: Control(sensorID: sensorID, indicators: indicators,
                                                              fieldFilters: fieldFilters))
        hold = launchServices.flatMap { reader in
            EventClassTable.eventClass(of: ES_EVENT_TYPE_NOTIFY_EXEC) == eventClass
                ? LaunchServicesHold(eventClass: eventClass, upgrader: LaunchedByParentUpgrader(reader: reader),
                                     emit: emit)
                : nil
        }
    }
    
    /// The client's handler: count the message, then, unless its field filter leaves it out and while recording,
    /// serialize it and emit it.
    ///
    /// - Parameter message: The message. Only valid during the call.
    func handle(_ message: UnsafePointer<es_message_t>) {
        counters.withLockUnchecked { counters in
            counters.messages &+= 1
            counters.sequences.observe(message)
        }
        gate.withLockUnchecked {
            guard let admission = control.withLockUnchecked({ $0.admit(message) }) else { return }
            let lane = LaneContext(eventClass: eventClass, sensorID: admission.sensorID, encoder: encoder,
                                   processPaths: processPaths, fileTypes: fileTypes,
                                   holdsForLaunchServices: hold != nil, indicators: admission.indicators,
                                   indicatorState: indicatorState)
            let serialized = serializer.serializeEvent(message, in: lane)
            if let counts = indicatorState.takeCounts() { counters.withLockUnchecked { $0.indicators = counts } }
            guard let serialized else {
                counters.withLockUnchecked { $0.serializationFailures &+= 1 }
                return
            }
            /// Under the control lock, so an event is never emitted once closing has given up on it.
            control.withLockUnchecked { state in
                guard !state.isAbandoned else { return }
                switch serialized {
                case .json(let json):
                    let event = CapturedEvent(json: json, eventClass: eventClass)
                    if let hold { hold.submit(event) } else { emit(event) }
                case .held(let exec):
                    hold?.hold(exec, stampedWith: admission.indicators)
                }
            }
        }
    }
    
    /// Send any held execs now. Call while closing.
    func releaseHeld() {
        hold?.close()
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
    
    /// Mute this process on the lane's client, as eslogger mutes itself. A refusal is logged.
    func muteSelf() {
        guard client?.muteProcess(audit_token_t.currentProcess) != true else { return }
        CaptureSession.logger.fault("""
            \(self.label, privacy: .public): couldn't mute this process on the \
            \(self.eventClass.rawValue, privacy: .public) client, so its own activity will be captured.
            """)
    }
    
    /// Make path mute calls on the lane's client, in order. A refusal is logged, with the client's count of them, and
    /// the rest still apply.
    ///
    /// - Parameter changes: The calls, in order.
    /// - Returns: `true` if the client accepted every call.
    @discardableResult
    func apply(_ changes: [MuteChange]) -> Bool {
        let refused = changes.filter { client?.setPathMute($0.mute, muted: $0.muted) != true }
        guard let first = refused.first else { return true }
        CaptureSession.logger.error("""
            \(self.label, privacy: .public): the \(self.eventClass.rawValue, privacy: .public) client refused \
            \(refused.count) of \(changes.count) path mute changes, such as \
            \(first.muted ? "muting" : "unmuting", privacy: .public) \(first.mute.path).
            """)
        return false
    }
    
    /// Start or stop serializing messages. Has no effect once the lane is closed.
    ///
    /// - Parameter recording: `true` to serialize and emit messages.
    func setRecording(_ recording: Bool) {
        control.withLock { $0.isRecording = recording }
    }
    
    /// Check these field filters from the next message on. Has no effect on an event already being built.
    ///
    /// - Parameter table: Each event type's field filter (``FieldFilter/table(_:)``).
    func setFieldFilters(_ table: ContiguousArray<FieldFilter?>) {
        control.withLock { $0.fieldFilters = table }
    }
    
    /// Stamp events with these indicators from the next message on. An event already being built keeps the set it
    /// was admitted with. The set replaced is released after the lock, should this be its last reference.
    ///
    /// - Parameter indicators: The set, or `nil` to stamp none.
    func setIndicators(_ indicators: CompiledIndicators?) {
        let replaced = control.withLock { state in
            defer { state.indicators = indicators }
            return state.indicators
        }
        withExtendedLifetime(replaced) {}
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
    
    /// Messages field filters left out while the lane was open, over its lifetime.
    var fieldFilteredMessages: UInt64 {
        control.withLock { $0.fieldFiltered.reduce(0, &+) }
    }
    
    /// Messages field filters left out while the lane was open, over its lifetime, by event type.
    ///
    /// - Returns: Counts by `es_event_type_t` raw value, for the types with any.
    func fieldFilteredByType() -> [Int: UInt64] {
        control.withLock { state in
            var counts: [Int: UInt64] = [:]
            for (type, count) in state.fieldFiltered.enumerated() where count > 0 { counts[type] = count }
            return counts
        }
    }
    
    /// The lane's lifetime counters.
    ///
    /// - Parameter subscribedEvents: How many events the lane's client is subscribed to.
    /// - Returns: The counters.
    func statistics(subscribedEvents: Int) -> CaptureLaneStatistics {
        /// Read before the counters' lock: the two locks are never held at once.
        let fieldFiltered = fieldFilteredByType()
        return counters.withLockUnchecked { counters in
            CaptureLaneStatistics(eventClass: eventClass, subscribedEvents: subscribedEvents,
                                  messages: counters.messages, dropped: counters.sequences.global.dropped,
                                  gaps: counters.sequences.global.gaps,
                                  regressions: counters.sequences.global.regressions,
                                  droppedByType: counters.sequences.droppedByType().byEventTypeName(),
                                  fieldFiltered: fieldFiltered.values.reduce(0, &+),
                                  fieldFilteredByType: fieldFiltered.byEventTypeName(),
                                  serializationFailures: counters.serializationFailures,
                                  hitCappedEvents: counters.indicators.hitCapped,
                                  truncatedEvaluations: counters.indicators.truncated,
                                  scanExhaustedEvents: counters.indicators.exhausted,
                                  undeterminedEvents: counters.indicators.undetermined)
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
    
    /// Wait, after ``close()``, until no event is being built or until `deadline`, send any held execs, then delete the
    /// lane's client: right away, or once a late event is done (it's dropped). Logs a late event, and a client whose
    /// deletion leaked Endpoint Security's resources. Call on the session's queue.
    ///
    /// - Parameter deadline: When to stop waiting for the event being built.
    func deleteClient(by deadline: DispatchTime) {
        guard waitUntilIdle(until: deadline) else {
            CaptureSession.logger.fault("""
                \(self.label, privacy: .public): the \(self.eventClass.rawValue, privacy: .public) client was still \
                building an event at the deadline. Dropped the event; the client is deleted once it's done.
                """)
            releaseHeld()
            return deleteClientOnceIdle()
        }
        releaseHeld()
        logDeletion(freed: deleteClient())
    }
    
    /// Hand the lane's client to a background queue that deletes it once no event is being built, so the session's
    /// queue never waits on a slow event. Nothing else calls the client by then: the session is stopped, and the lane
    /// is closed.
    private func deleteClientOnceIdle() {
        guard let client else { return }
        self.client = nil
        DispatchQueue.global(qos: .utility).async { [gate] in
            gate.withLock {}
            self.logDeletion(freed: client.delete())
        }
    }
    
    /// Log a client whose deletion leaked Endpoint Security's resources.
    ///
    /// - Parameter freed: Whether Endpoint Security freed the client's resources.
    private func logDeletion(freed: Bool) {
        guard !freed else { return }
        CaptureSession.logger.error("""
            \(self.label, privacy: .public): Endpoint Security leaked the \
            \(self.eventClass.rawValue, privacy: .public) client's resources while deleting it.
            """)
    }
}
