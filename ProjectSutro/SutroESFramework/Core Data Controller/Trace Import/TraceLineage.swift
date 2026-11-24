//
//  TraceLineage.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - A trace's lineage
/// The ancestors of a trace's processes, rebuilt from the trace alone: its forks and execs, and the snapshots of
/// the processes that were running before it began (``ProcessSnapshot``). Each start of the Mac a trace holds has
/// its own table (``Tables``).
///
/// The whole trace is read before any of its events is evaluated. A capture's lanes hand their events over in
/// their own order, so a file event can come in a trace before the exec of the process it's from, and the Security
/// Extension, which read that process's parents from the system, has no counterpart here. Nothing is forgotten as
/// the trace is read, so a process is found by its own key however much later it's asked for, and only by its own
/// key (``ProcessLineage/replaying()``).
enum TraceLineage {
    /// A snapshot's key, as any record that is one holds it.
    private static let snapshot = Data(#""process_snapshot""#.utf8)
    /// The key of an exec's or a fork's ancestors, as any record that names some holds it.
    private static let ancestors = Data(#""ancestor_keys""#.utf8)

    /// The snapshot a trace's record is.
    ///
    /// - Parameter record: One record of a trace.
    /// - Returns: The snapshot, or `nil` for an event.
    static func snapshot(in record: Data) -> ProcessSnapshotRecord? {
        record.range(of: snapshot) == nil ? nil : ProcessSnapshotRecord.read(record)
    }

    /// The tables a trace's records make, one for each start of the Mac its records are from
    /// (`boot_session_uuid`): a process's key means one process only within one. Records that don't say which
    /// start they're from, as Mac Monitor 3.1's don't, share a table.
    typealias Tables = [String?: ProcessLineage]

    /// Tell a trace's tables what one record says of processes: a snapshot describes one, and a fork or an exec
    /// creates one. A record that says neither isn't decoded.
    ///
    /// An exec is stamped with the ancestors the Security Extension knew for it, which it took from the fork. When
    /// the trace holds neither that fork nor a snapshot of the process, the keys stand in for them. The exec's
    /// parent token alone can say otherwise: launchd, once the process that forked it has exited, or a newer
    /// program, once that process has exec'd again.
    ///
    /// - Parameters:
    ///   - record: One record of a trace.
    ///   - tables: The tables.
    static func note(_ record: Data, in tables: inout Tables) {
        if let snapshot = snapshot(in: record) {
            guard let program = snapshot.process_snapshot.program else { return }
            table(for: snapshot.boot_session_uuid, in: &tables)
                .describe(program, ancestors: snapshot.process_snapshot.ancestors)
        } else if record.range(of: ancestors) != nil, let message = try? TraceImporter.message(from: record) {
            let table = table(for: message.boot_session_uuid, in: &tables)
            if case .exec(let exec) = message.event, let keys = exec.ancestor_keys,
               let process = message.process.audit_token.map(ProcessKey.init), table.program(process) == nil {
                table.describe(ProcessProgram(key: process), ancestors: keys.compactMap { ProcessKey($0) })
            }
            table.note(message, at: 0)
        }
    }

    /// The table for one start of the Mac, made when it's first asked for.
    ///
    /// - Parameters:
    ///   - boot: The boot session, or `nil` for records that don't say.
    ///   - tables: The tables.
    /// - Returns: The table.
    private static func table(for boot: String?, in tables: inout Tables) -> ProcessLineage {
        if let table = tables[boot] { return table }
        let table = ProcessLineage.replaying()
        tables[boot] = table
        return table
    }

    /// The tables a trace's records make.
    ///
    /// - Parameter url: The trace: JSONL, or any trace File > Open Trace reads.
    /// - Returns: The tables, by boot session. None for a trace recorded without lineage.
    /// - Throws: The error opening or reading the trace.
    static func tables(of url: URL) throws -> Tables {
        var tables = Tables()
        let reader = try TraceRecordReader(url: url)
        while let record = try reader.next() {
            if case .object(let data, _) = record { note(data, in: &tables) }
        }
        return tables
    }
}
