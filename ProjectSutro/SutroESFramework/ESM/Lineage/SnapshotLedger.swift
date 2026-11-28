//
//  SnapshotLedger.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - Snapshot ledger
/// Which processes one capture session has described, so each is described once: by its own exec or fork, or else
/// by a snapshot written before the first record that's from it or names it (``ProcessSnapshot``).
///
/// **Threading:** thread-safe. A session's lanes share it.
public final class SnapshotLedger: @unchecked Sendable {
    /// How many processes it remembers. Past it, it forgets them all: a process seen again is then described
    /// again, which costs a line and breaks nothing.
    static let capacity = 65_536
    /// Guards the processes described.
    private let lock = NSLock()
    /// The processes described so far.
    private var described = Set<ProcessKey>()

    public init() {}

    /// A record that describes a process is being written: an exec's target, a fork's child. It needs no snapshot.
    ///
    /// - Parameter key: The process.
    public func recorded(_ key: ProcessKey) {
        lock.withLock { _ = insert(key) }
    }

    /// Has something described a process already?
    ///
    /// - Parameter key: The process.
    /// - Returns: Whether it has.
    public func isDescribed(_ key: ProcessKey) -> Bool {
        lock.withLock { described.contains(key) }
    }

    /// The snapshots to write before a record, for a chain of processes it's from or names: one for each that
    /// nothing has described, farthest first, so a snapshot's own ancestors come before it. Each snapshot names the
    /// rest of the chain as its ancestors, as the record does.
    ///
    /// A process known only by its key has none, and isn't counted as described: its exec may be on its way, or
    /// the processes that were running may not have been read yet.
    ///
    /// - Parameter chain: The processes, nearest first, as the lineage table has them.
    /// - Returns: The snapshots, in the order to write them.
    public func due(for chain: [ProcessProgram]) -> [ProcessSnapshot] {
        lock.withLock {
            chain.indices.reversed().compactMap { index in
                let program = chain[index]
                guard program.isKnown, !program.key.isRoot, insert(program.key) else { return nil }
                return ProcessSnapshot(program, ancestors: chain[(index + 1)...].map(\.key))
            }
        }
    }

    /// Remember a process as described. Call under the lock.
    ///
    /// - Parameter key: The process.
    /// - Returns: Whether it's newly described.
    private func insert(_ key: ProcessKey) -> Bool {
        if described.count >= Self.capacity { described.removeAll(keepingCapacity: true) }
        return described.insert(key).inserted
    }
}


// MARK: - A lane's snapshots
/// The snapshots a capture lane owes before the event it's building, encoded and waiting for the lane to emit
/// them. The lane's own: only one thread uses it at a time.
final class LaneSnapshots {
    /// How many processes the lane remembers having looked at, before it starts over.
    static let capacity = 16_384
    /// The session's ledger.
    let ledger: SnapshotLedger
    /// The lines waiting to be emitted, in order.
    private var pending: [Data] = []
    /// The processes whose events the lane has already seen described, so most events ask the ledger nothing.
    private var seen = Set<ProcessKey>()

    /// - Parameter ledger: The session's ledger.
    init(ledger: SnapshotLedger) {
        self.ledger = ledger
    }

    /// Queue the snapshots an event owes.
    ///
    /// - An exec or a fork owes one for each ancestor it names, and the process it creates counts as described.
    /// - Any other event owes one for its own process and that process's ancestors, the first time the lane sees
    ///   the process, unless a record described it: a process that was running before the capture has no exec
    ///   in the trace, and nothing else would say who its ancestors are. The ancestors are looked up as an
    ///   indicator's are, reading the system or waiting for a tree that's gone
    ///   (``ProcessLineage/ancestors(of:parent:reading:at:chain:)``), so a trace replays as the capture
    ///   evaluated it. A process the table still wasn't told of is described as the event itself says it: it may
    ///   have no other event, and a capture that leaves execs out would otherwise never say what it was.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - ancestors: The ancestors an exec or a fork was stamped with (``Message/stampAncestorKeys(from:)``).
    ///   - lineage: The table.
    func describe(_ event: Message, naming ancestors: [ProcessProgram]?, from lineage: ProcessLineage) {
        let chain: [ProcessProgram]
        switch event.event {
        case .exec(let exec):
            if let created = exec.target.audit_token { ledger.recorded(ProcessKey(created)) }
            chain = ancestors ?? []
        case .fork(let fork):
            if let created = fork.child.audit_token { ledger.recorded(ProcessKey(created)) }
            chain = ancestors ?? []
        default:
            guard let key = event.process.audit_token.map(ProcessKey.init), !seen.contains(key) else { return }
            remember(key)
            guard !ledger.isDescribed(key) else { return }
            let parent = event.process.parent_audit_token.map(ProcessKey.init)
            let ancestors = lineage.ancestors(of: key, parent: parent, reading: true,
                                              at: UInt64(clamping: event.mach_time))
            let known = lineage.program(key).flatMap { $0.isKnown ? $0 : nil }
            guard let program = known ?? ProcessProgram(event.process) else { return }
            chain = [program] + ancestors
        }
        queue(chain, before: event)
    }

    /// Queue the snapshots a network flow owes: one for its process and its ancestors, the first time the lane sees
    /// the process, unless a record described it. Only a program the lineage table knows is described. A flow's
    /// process is only what its socket said, so for one the table doesn't know nothing is written and nothing is
    /// remembered. The process's next record, its flow's close at the latest, tries again.
    ///
    /// - Parameters:
    ///   - event: The flow's event.
    ///   - lineage: The table.
    func describeFlow(_ event: Message, from lineage: ProcessLineage) {
        guard let key = event.process.audit_token.map(ProcessKey.init), !seen.contains(key) else { return }
        guard !ledger.isDescribed(key) else { return remember(key) }
        guard let program = lineage.program(key), program.isKnown else { return }
        remember(key)
        queue([program] + lineage.ancestors(of: key, reading: true, at: UInt64(clamping: event.mach_time)),
              before: event)
    }

    /// Queue the snapshots due for a chain of processes, before an event that names them.
    ///
    /// - Parameters:
    ///   - chain: The processes, nearest first.
    ///   - event: The event, whose Sensor ID and boot session the snapshots carry.
    private func queue(_ chain: [ProcessProgram], before event: Message) {
        guard !chain.isEmpty else { return }
        pending += ledger.due(for: chain).compactMap {
            ProcessSnapshotRecord($0, sensorID: event.sensor_id, bootSession: event.boot_session_uuid).line
        }
    }

    /// Take the lines waiting to be emitted.
    ///
    /// - Returns: The lines, in order. Empty for nearly every event.
    func take() -> [Data] {
        guard !pending.isEmpty else { return [] }
        defer { pending.removeAll(keepingCapacity: true) }
        return pending
    }

    /// Remember that a process's events need nothing more.
    ///
    /// - Parameter key: The process.
    private func remember(_ key: ProcessKey) {
        if seen.count >= Self.capacity { seen.removeAll(keepingCapacity: true) }
        seen.insert(key)
    }
}
