//
//  StreamSnapshots.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - A stream's snapshots
/// The process snapshots written among a stream's or an export's records (``ProcessSnapshot``): before the first
/// record written that's from a process, or names it as an ancestor, that process's snapshot, unless a record
/// written before describes it.
///
/// The Security Extension sends a snapshot for each process that started before the capture. Whatever writes only
/// some of a trace's events can also leave out the exec or the fork that described a process, so each of those is
/// kept here as a snapshot too (``SnapshotTable``). Either way a snapshot is written only once something written
/// needs it, and once.
///
/// A snapshot can come after the record that needs it: an app's exec is held for Launch Services while its
/// children's events go on. It's then written as soon as it comes (``overdue()``), which a reader that takes in
/// the whole trace first reads the same (``TraceLineage``).
///
/// Not thread-safe: a pipeline joins its chunks on one thread, and an export writes on one queue.
final class StreamSnapshots {
    /// What a record says of processes.
    struct Naming {
        /// The process the record is from, for an event that creates none. An exec's and a fork's ancestors say
        /// everything about theirs.
        let subject: ProcessKey?
        /// The process an exec or a fork creates.
        let creates: ProcessKey?
        /// The ancestors an exec or a fork names, nearest first.
        let names: [ProcessKey]
        /// The created process as a snapshot, for an exec or a fork that isn't written.
        let snapshot: ProcessSnapshotRecord?

        /// - Parameter message: An event.
        /// - Returns: What it says, or `nil` for an event with no process, and for an exec or a fork that carries
        ///   no keys: a capture without lineage.
        init?(_ message: Message) {
            let created: Process, commandLine: String?, named: [String]?
            switch message.event {
            case .exec(let exec): (created, commandLine, named) = (exec.target, exec.command_line, exec.ancestor_keys)
            case .fork(let fork): (created, commandLine, named) = (fork.child, nil, fork.ancestor_keys)
            default:
                guard let token = message.process.audit_token else { return nil }
                self.init(from: ProcessKey(token))
                return
            }
            guard let named, let token = created.audit_token else { return nil }
            let program = ProcessProgram(key: ProcessKey(token), path: created.executable?.path,
                                         commandLine: commandLine, signingID: created.signing_id,
                                         teamID: created.team_id,
                                         codesigningType: created.codesigning_type.rawValue)
            self.init(creating: program, naming: named, sensorID: message.sensor_id,
                      bootSession: message.boot_session_uuid)
        }

        /// What an exec or a fork says.
        ///
        /// - Parameters:
        ///   - program: The process the record creates.
        ///   - names: Its ancestors' keys, nearest first.
        ///   - sensorID: The record's Sensor ID.
        ///   - bootSession: The record's boot session.
        init(creating program: ProcessProgram, naming names: [String], sensorID: String?, bootSession: String?) {
            subject = nil
            creates = program.key
            self.names = names.compactMap { ProcessKey($0) }
            snapshot = ProcessSnapshotRecord(ProcessSnapshot(program, ancestors: self.names), sensorID: sensorID,
                                             bootSession: bootSession)
        }

        /// What any other event says.
        ///
        /// - Parameter subject: The process the record is from.
        init(from subject: ProcessKey) {
            self.subject = subject
            (creates, names, snapshot) = (nil, [], nil)
        }
    }

    /// How many processes are remembered as described, and as needed. Past it, they're forgotten: a snapshot may
    /// then be written twice in a stream of that many processes. `nil` remembers them all, for an export.
    private let capacity: Int?
    /// The snapshots not written yet.
    private var waiting: SnapshotTable
    /// The processes the output has described: by a record, or by a snapshot.
    private var described = Set<ProcessKey>()
    /// The processes a written record needed that nothing described: their snapshots are written when they come.
    private var needed = Set<ProcessKey>()
    /// The needed processes whose snapshots have come.
    private var late: [ProcessKey] = []
    /// Has anything said the trace tracks lineage: a snapshot, or an exec or a fork with ancestor keys? Until it
    /// has, a record's own process isn't looked for where looking costs a fetch.
    private var tracksLineage = false
    /// Pretty-prints a snapshot, for a stream whose records are. `nil` writes a snapshot's own line
    /// (``ProcessSnapshotRecord/line``).
    private let pretty: JSONEncoder?
    /// Finds a process nothing here describes, such as one whose exec an export of a selection leaves out. `nil`
    /// finds none.
    var resolve: ((ProcessKey) -> ProcessSnapshotRecord?)?

    /// - Parameters:
    ///   - pretty: Pretty-print each snapshot, as the stream's records are.
    ///   - capacity: How many processes are remembered as described. `nil` remembers them all.
    ///   - waiting: The snapshots to start with.
    init(pretty: Bool = false, capacity: Int? = 16_384, waiting: SnapshotTable = SnapshotTable()) {
        self.capacity = capacity
        self.waiting = waiting
        tracksLineage = !waiting.isEmpty
        self.pretty = pretty ? JSONEncoder() : nil
        self.pretty?.outputFormatting = [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted]
    }

    /// Take the snapshots out of a batch, and keep them.
    ///
    /// - Parameter batch: What the Security Extension sent: events, and snapshots among them.
    /// - Returns: The events, in order.
    func sift(_ batch: [Data]) -> [Data] {
        guard batch.contains(where: ProcessSnapshotRecord.isSnapshot) else { return batch }
        return batch.filter { line in
            guard ProcessSnapshotRecord.isSnapshot(line) else { return true }
            if let record = ProcessSnapshotRecord.read(line) { keep(record, made: false) }
            return false
        }
    }

    /// Keep a snapshot until something written needs its process.
    ///
    /// - Parameters:
    ///   - record: The snapshot.
    ///   - made: Was it made from an exec or a fork that isn't written? `false` for one that was sent.
    func keep(_ record: ProcessSnapshotRecord, made: Bool) {
        guard let key = ProcessKey(record.process_snapshot.key), !described.contains(key) else { return }
        tracksLineage = true
        waiting.keep(record, made: made)
        if needed.remove(key) != nil { late.append(key) }
    }

    /// Might a record owe a snapshot? Not when its process is described and it names no ancestors, as nearly
    /// every record is.
    ///
    /// - Parameter naming: What the record says of processes.
    /// - Returns: Whether to ask ``records(before:)``.
    func owes(_ naming: Naming) -> Bool {
        naming.creates != nil || naming.subject.map { !described.contains($0) } ?? false
    }

    /// The snapshots to write before a record: one for its process and each ancestor it names that nothing written
    /// describes, and for each those name in turn, farthest first. The process the record creates then counts as
    /// described.
    ///
    /// - Parameter naming: What the record says of processes.
    /// - Returns: Each snapshot's JSON, in the order to write them. Empty for nearly every record.
    func records(before naming: Naming) -> [Data] {
        if naming.creates != nil { tracksLineage = true }
        let owed = snapshots(for: (naming.subject.map { [$0] } ?? []) + naming.names,
                             resolvingFirst: naming.subject == nil || tracksLineage)
        if let created = naming.creates {
            describe(created)
            waiting.drop(created)
            needed.remove(created)
        }
        return owed.compactMap(encoded)
    }

    /// The same snapshots as lines.
    ///
    /// - Parameter naming: What the record says of processes.
    /// - Returns: The snapshots' lines, each ending with a newline.
    func lines(before naming: Naming) -> Data {
        Self.lines(records(before: naming))
    }

    /// The snapshots that came after the records that needed them, to write now.
    ///
    /// - Returns: Each snapshot's JSON, in the order to write them. Nearly always empty.
    func overdue() -> [Data] {
        guard !late.isEmpty else { return [] }
        defer { late.removeAll() }
        return snapshots(for: late, resolvingFirst: false).compactMap(encoded)
    }

    /// A snapshot's JSON, as the stream's records are written.
    ///
    /// - Parameter record: The snapshot.
    /// - Returns: Its line, or pretty-printed JSON.
    private func encoded(_ record: ProcessSnapshotRecord) -> Data? {
        pretty.map { try? $0.encode(record) } ?? record.line
    }

    /// Join snapshots' JSON into lines.
    ///
    /// - Parameter records: Each snapshot's JSON.
    /// - Returns: The lines, each ending with a newline.
    static func lines(_ records: [Data]) -> Data {
        records.reduce(into: Data()) { lines, record in
            lines.append(record)
            lines.append(0x0A)
        }
    }

    /// The snapshots of some processes and of the ancestors those name in turn, each once, farthest first. A
    /// process with none is remembered as needed.
    ///
    /// - Parameters:
    ///   - keys: The processes, nearest first.
    ///   - resolvingFirst: May the first be looked for with ``resolve``? The rest always may.
    /// - Returns: The snapshots, in the order to write them.
    private func snapshots(for keys: [ProcessKey], resolvingFirst: Bool) -> [ProcessSnapshotRecord] {
        var owed: [ProcessSnapshotRecord] = []
        var keys = keys
        var index = 0
        while index < keys.count {
            let key = keys[index]
            index += 1
            guard !key.isRoot, !described.contains(key) else { continue }
            guard let record = waiting.take(key) ?? (index > 1 || resolvingFirst ? resolve?(key) : nil) else {
                if needed.count >= capacity ?? .max { needed.removeAll(keepingCapacity: true) }
                needed.insert(key)
                continue
            }
            describe(key)
            owed.append(record)
            keys += record.process_snapshot.ancestors
        }
        return owed.reversed()
    }

    /// Count a process as described.
    ///
    /// - Parameter key: The process.
    private func describe(_ key: ProcessKey) {
        if described.count >= capacity ?? .max { described.removeAll(keepingCapacity: true) }
        described.insert(key)
    }
}
