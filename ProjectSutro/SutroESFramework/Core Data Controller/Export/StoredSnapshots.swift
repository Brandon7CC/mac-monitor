//
//  StoredSnapshots.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation
import CoreData


// MARK: - Stored snapshots
/// The process snapshots that go with the events a store holds (``ProcessSnapshot``): the ones the Security
/// Extension sent with a recording or a trace held, and one made from each exec and fork the recording had, the
/// oldest dropped first (``SnapshotTable``). An export writes each before the first record that needs it.
///
/// The made ones are what a Clear and Mac Monitor's own filters leave of a process: the exec that described it may
/// be gone from the store, or never have been kept, while later events still name it.
///
/// They're kept in memory, not in the store, which starts empty every time Mac Monitor opens.
///
/// **Threading:** thread-safe.
public final class StoredSnapshots: @unchecked Sendable {
    private let lock = NSLock()
    private var table = SnapshotTable()

    public init() {}

    /// Keep a snapshot the Security Extension sent, or a trace held.
    ///
    /// - Parameter record: The snapshot.
    public func add(_ record: ProcessSnapshotRecord) {
        lock.withLock { table.keep(record, made: false) }
    }

    /// Keep the process an exec or a fork created as a snapshot. Any other event, and one that carries no ancestor
    /// keys, is left alone.
    ///
    /// - Parameter message: The event, as it was received.
    public func add(creatorOf message: Message) {
        switch message.event {
        case .exec, .fork:
            guard let snapshot = StreamSnapshots.Naming(message)?.snapshot else { return }
            lock.withLock { table.keep(snapshot, made: true) }
        default:
            return
        }
    }

    /// The snapshots as they are now, for an export.
    var current: SnapshotTable {
        lock.withLock { table }
    }
}


// MARK: - What a stored event says of processes
extension StreamSnapshots.Naming {
    /// - Parameter message: A stored event.
    /// - Returns: What it says, or `nil` for an event with no process, and for an exec or a fork that carries no
    ///   keys.
    init?(_ message: ESMessage) {
        let created: ESProcess, commandLine: String?, named: [String]?
        if let exec = message.event.exec {
            (created, commandLine, named) = (exec.target, exec.command_line, exec.ancestor_keys)
        } else if let fork = message.event.fork {
            (created, commandLine, named) = (fork.child, nil, fork.ancestor_keys)
        } else {
            guard let token = message.process.audit_token else { return nil }
            self.init(from: ProcessKey(pid: token.pid, pidversion: token.pidversion))
            return
        }
        guard let named, let token = created.audit_token else { return nil }
        let program = ProcessProgram(key: ProcessKey(pid: token.pid, pidversion: token.pidversion),
                                     path: created.executable?.path, commandLine: commandLine,
                                     signingID: created.signing_id, teamID: created.team_id,
                                     codesigningType: created.codesigning_type)
        self.init(creating: program, naming: named, sensorID: message.sensor_id,
                  bootSession: message.boot_session_uuid)
    }
}
