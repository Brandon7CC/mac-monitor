//
//  FlowLane.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
import os


// MARK: - Flow lane
/// A capture session's network lane: the consumer it registers with the network statistics client
/// (``NetworkStatisticsClient``), and the work done for each flow on the client's delivery queue.
///
/// It's built as a ``CaptureLane`` is, with its own locks, encoder, indicator values and snapshots on the session's
/// ledger. Its counters are its own (``FlowLaneStatistics``). Flows have no sequence numbers, and nothing Endpoint
/// Security drops is a flow.
///
/// **Control:** whether to record, which flow events, the Sensor ID, the indicators, the mutes and whether URLs keep
/// their paths are read under a lock of their own as each record is handled. So changing any of them never waits for a
/// flow being built.
///
/// **Gate:** the gate's lock is held while a record is built and emitted. Once ``close()`` has marked the lane closed
/// and ``waitUntilIdle(until:)`` has taken the gate, the lane emits nothing more. One still being built at the
/// deadline is dropped.
///
/// **Registration:** only the session's queue registers and unregisters the lane, and reads what registration keeps.
/// It never does so on the client's queues, or with the lane's locks held.
final class FlowLane: FlowConsumer {
    /// What the handler checks before it builds a record's event.
    private struct Control {
        var isRecording = false
        /// Closed for good. The session is stopping or has drained.
        var isClosed = false
        /// Closing gave up waiting for the flow being built. That flow is dropped rather than emitted late.
        var isAbandoned = false
        var sensorID: String
        var indicators: CompiledIndicators?
        var chains: SessionChains?
        /// The flow events the session subscribes to.
        var subscribed = Set<MacMonitorEvent>()
        var mutes: FlowMutes
        /// Keep a URL's path?
        var recordsURLPaths: Bool
        /// Records turned away while not recording, and those a mute covered.
        var skipped: UInt64 = 0, muted: UInt64 = 0

        /// What to build a record's event with. A record is admitted while the lane is open and recording, for a
        /// subscribed event, when no mute covers it. The Security Extension's own sockets are left out when the
        /// session mutes itself.
        ///
        /// - Parameters:
        ///   - record: The flow.
        ///   - mutesSelf: Leave out the Security Extension's own sockets?
        /// - Returns: What to build with, or `nil` to leave the record out.
        mutating func admit(_ record: FlowRecord, mutesSelf: Bool) -> Admission? {
            let event: MacMonitorEvent = record.kind == .opened ? .new_flow : .flow_closed
            guard !isClosed, subscribed.contains(event), !(mutesSelf && record.isOwn) else { return nil }
            if mutes.mutes(record.process.program?.path, for: event) {
                muted &+= 1
                return nil
            }
            guard isRecording else {
                skipped &+= 1
                return nil
            }
            return Admission(sensorID: sensorID, indicators: indicators, chains: chains,
                             recordsURLPaths: recordsURLPaths)
        }
    }

    /// What an admitted record is built with. It's read in one go, under the control lock.
    private struct Admission {
        let sensorID: String
        let indicators: CompiledIndicators?
        let chains: SessionChains?
        let recordsURLPaths: Bool
    }

    /// What the lane has seen of the client's records.
    private struct Counters {
        /// Records handed to the lane.
        var records: UInt64 = 0
        var serializationFailures: UInt64 = 0
        /// The indicator counts the lane last took from its ``LaneIndicators``.
        var indicators = IndicatorCounts()
    }

    private let client: NetworkStatisticsClient
    private let control: OSAllocatedUnfairLock<Control>
    /// Held while a record is built and emitted.
    private let gate = OSAllocatedUnfairLock()
    private let counters = OSAllocatedUnfairLock(uncheckedState: Counters())
    /// Only used under ``gate``.
    private let encoder = StreamingJSONEncoder()
    /// Only used under ``gate``.
    private let indicatorState = LaneIndicators()
    /// The lineage table the session keeps told, or `nil` when lineage isn't tracked.
    private let lineage: ProcessLineage?
    /// The snapshots owed for the flows' processes, when lineage is tracked. Only used under ``gate``.
    private let snapshots: LaneSnapshots?
    private let mutesSelf: Bool
    /// This Mac's macOS version, System Integrity Protection status and boot session, read once.
    private let macOS: String, sipStatus: SIPStatus?, bootSession: String?
    private let emit: (CapturedEvent) -> Void

    /// Is the lane registered with the client?
    private(set) var isRegistered = false
    /// Has it ever been?
    private(set) var wasRegistered = false
    /// The client's counts when the lane last registered.
    private var baseline = FlowCounts()
    /// What the client couldn't report during the lane's earlier registrations.
    private var earlier = FlowLaneStatistics()
    /// Why the client couldn't open its socket, the last time it couldn't.
    private(set) var problem: String?

    /// A lane that isn't recording or registered.
    ///
    /// - Parameters:
    ///   - client: The network statistics client to register with.
    ///   - sensorID: The Sensor ID to stamp on events.
    ///   - indicators: The indicators to stamp events with. `nil` stamps none.
    ///   - chains: The session's chains for their sequences.
    ///   - mutes: The session's mutes for flows.
    ///   - mutesSelf: Leave out the Security Extension's own sockets?
    ///   - recordsURLPaths: Keep a URL's path?
    ///   - lineage: The lineage table the session keeps told. `nil` tracks none.
    ///   - snapshots: The session's ledger of the processes it has described.
    ///   - macOS: The macOS version to stamp on events.
    ///   - sipStatus: System Integrity Protection's status to stamp on events.
    ///   - bootSession: The boot session's identifier to stamp on events.
    ///   - emit: Receives each event in order, under the lane's locks. It must not block.
    init(client: NetworkStatisticsClient, sensorID: String, indicators: CompiledIndicators?, chains: SessionChains?,
         mutes: FlowMutes, mutesSelf: Bool, recordsURLPaths: Bool, lineage: ProcessLineage?,
         snapshots: SnapshotLedger?, macOS: String = Message.currentMacOSVersion(),
         sipStatus: SIPStatus? = SIPStatus.current, bootSession: String? = BootSession.current,
         emit: @escaping (CapturedEvent) -> Void) {
        self.client = client
        control = OSAllocatedUnfairLock(initialState: Control(sensorID: sensorID, indicators: indicators,
                                                              chains: chains, mutes: mutes,
                                                              recordsURLPaths: recordsURLPaths))
        self.lineage = lineage
        self.snapshots = lineage == nil ? nil : snapshots.map(LaneSnapshots.init)
        self.mutesSelf = mutesSelf
        (self.macOS, self.sipStatus, self.bootSession) = (macOS, sipStatus, bootSession)
        self.emit = emit
    }

    /// The client's handler. It counts the record, then builds the event of an admitted one and emits it after the
    /// snapshots it owes.
    ///
    /// - Parameter record: A flow that opened or closed.
    func handle(_ record: FlowRecord) {
        counters.withLockUnchecked { $0.records &+= 1 }
        gate.withLockUnchecked {
            guard let admission = control.withLockUnchecked({ $0.admit(record, mutesSelf: mutesSelf) }) else { return }
            var event = Message(flow: record, keepingURLPath: admission.recordsURLPaths, sensorID: admission.sensorID,
                                macOS: macOS, sipStatus: sipStatus, bootSession: bootSession)
            if let lineage { snapshots?.describeFlow(event, from: lineage) }
            indicatorState.stamp(&event, with: admission.indicators, chains: admission.chains, lineage: lineage)
            let described = snapshots?.take() ?? []
            if let counts = indicatorState.takeCounts() { counters.withLockUnchecked { $0.indicators = counts } }
            let json = try? encoder.encode(event)
            if json == nil { counters.withLockUnchecked { $0.serializationFailures &+= 1 } }
            /// Under the control lock, so nothing is emitted once closing has given up on it.
            control.withLockUnchecked { state in
                guard !state.isAbandoned else { return }
                /// Ahead of the event that names them. They stand on their own when it couldn't be encoded.
                for line in described { emit(CapturedEvent(json: line, eventClass: .network)) }
                if let json { emit(CapturedEvent(json: json, eventClass: .network)) }
            }
        }
    }

    // MARK: Registration

    /// Register with the client, which opens its socket for the first consumer. The client's counts as the lane
    /// joins are its baseline. Call on the session's queue.
    ///
    /// - Returns: `false` when the socket couldn't be opened (``problem``). The lane then isn't registered.
    func register() -> Bool {
        guard !isRegistered else { return true }
        let joined = client.register(self)
        guard joined.state != .unavailable else {
            problem = joined.reason ?? "The network statistics socket couldn't be opened."
            return false
        }
        (isRegistered, wasRegistered, problem, baseline) = (true, true, nil, joined.counts)
        return true
    }

    /// Unregister from the client, which closes its socket for the last consumer. What the client couldn't report
    /// meanwhile is kept. Call on the session's queue.
    func unregister() {
        guard isRegistered else { return }
        earlier = losses(upTo: client.unregister(self))
        isRegistered = false
    }

    /// What the client couldn't report while the lane was registered, with what it couldn't before.
    ///
    /// - Parameter now: The client's counts now.
    /// - Returns: The counters. Only the client's three are set.
    private func losses(upTo now: FlowCounts) -> FlowLaneStatistics {
        var losses = earlier
        losses.socketsLost += max(0, now.socketsLost - baseline.socketsLost)
        losses.closedWithoutCounts += max(0, now.closedWithoutCounts - baseline.closedWithoutCounts)
        losses.overBudget += max(0, now.overBudget - baseline.overBudget)
        return losses
    }

    /// The lane's lifetime counters. Call on the session's queue.
    ///
    /// - Returns: The counters.
    func statistics() -> FlowLaneStatistics {
        var statistics = isRegistered ? losses(upTo: client.status.counts) : earlier
        (statistics.skipped, statistics.muted) = control.withLock { ($0.skipped, $0.muted) }
        counters.withLockUnchecked { counters in
            statistics.records = counters.records
            statistics.serializationFailures = counters.serializationFailures
            statistics.hitCappedEvents = counters.indicators.hitCapped
            statistics.undeterminedEvents = counters.indicators.undetermined
        }
        return statistics
    }

    // MARK: Control

    /// Build events for these flow events from the next record on.
    ///
    /// - Parameter events: The flow events the session subscribes to.
    func setSubscribed(_ events: Set<MacMonitorEvent>) {
        control.withLock { $0.subscribed = events }
    }

    /// Start or stop building events. Has no effect once the lane is closed.
    ///
    /// - Parameter recording: `true` to build and emit events.
    func setRecording(_ recording: Bool) {
        control.withLock { $0.isRecording = recording }
    }

    /// Stamp events with another Sensor ID.
    ///
    /// - Parameter sensorID: The Sensor ID to stamp on events from now on.
    func setSensorID(_ sensorID: String) {
        control.withLock { $0.sensorID = sensorID }
    }

    /// Mute flows with another set of mutes.
    ///
    /// - Parameter mutes: The mutes to apply from the next record on.
    func setMutes(_ mutes: FlowMutes) {
        control.withLock { $0.mutes = mutes }
    }

    /// Keep each URL's path, or end it at its host and port.
    ///
    /// - Parameter keeps: Keep a URL's path from the next record on?
    func setRecordsURLPaths(_ keeps: Bool) {
        control.withLock { $0.recordsURLPaths = keeps }
    }

    /// Stamp events with these indicators from the next record on. The set replaced is released after the lock,
    /// should this be its last reference.
    ///
    /// - Parameters:
    ///   - indicators: The set, or `nil` to stamp none.
    ///   - chains: The session's chains for its sequences.
    func setIndicators(_ indicators: CompiledIndicators?, chains: SessionChains?) {
        let replaced = control.withLock { state in
            defer { (state.indicators, state.chains) = (indicators, chains) }
            return (state.indicators, state.chains)
        }
        withExtendedLifetime(replaced) {}
    }

    /// Records skipped while the lane was open but not recording, over its lifetime.
    var skippedMessages: UInt64 {
        control.withLock { $0.skipped }
    }

    // MARK: Closing

    /// Deliver every flow the client has read so far, then close. Call on the session's queue while registered.
    ///
    /// - Parameter completion: Called once, on the client's delivery queue.
    func drain(then completion: @escaping () -> Void) {
        client.drain { [self] in
            close()
            completion()
        }
    }

    /// Stop for good, without waiting. Records still on their way are ignored. One being built still goes out,
    /// unless ``waitUntilIdle(until:)`` gives up on it.
    func close() {
        control.withLock { $0.isClosed = true }
    }

    /// Wait, after ``close()``, until no record is being built, or until a deadline.
    ///
    /// - Parameter deadline: When to give up.
    /// - Returns: `true` once none is being built. `false` if one still was at the deadline, which is then dropped.
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
}
