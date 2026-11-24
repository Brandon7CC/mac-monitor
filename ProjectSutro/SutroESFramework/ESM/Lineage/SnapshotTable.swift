//
//  SnapshotTable.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - Snapshot table
/// Process snapshots waiting to be written, by their process's key, in two kinds:
///
/// - **Sent:** the ones the Security Extension sent, or a trace held. Each is the only description there is of its
///   process, so they're kept until they're used.
/// - **Made:** the ones made from an exec or a fork, in case that event isn't written. There's one for every
///   process, most of which nothing ever names, so the oldest are dropped past ``Limit``.
///
/// Not thread-safe.
struct SnapshotTable {
    /// How much a table keeps of the snapshots made from execs and forks.
    struct Limit: Equatable {
        /// The most of them.
        var count = 16_384
        /// The most their command lines and paths may hold together, in bytes.
        var bytes = 16 << 20
    }

    /// How many sent snapshots are kept. Past it, they're all forgotten: far more than a Mac has processes.
    static let sentCapacity = 65_536
    /// How much is kept of the made ones. `nil` keeps them all.
    let limit: Limit?
    private var sent: [ProcessKey: ProcessSnapshotRecord] = [:]
    private var made: [ProcessKey: ProcessSnapshotRecord] = [:]
    /// The made ones' keys, oldest first, from ``oldest`` on.
    private var order: [ProcessKey] = []
    /// Where the oldest made one is in ``order``.
    private var oldest = 0
    /// What the made ones weigh (``weight(of:)``).
    private var bytes = 0

    /// - Parameter limit: How much is kept of the snapshots made from execs and forks. `nil` keeps them all.
    init(limit: Limit? = Limit()) {
        self.limit = limit
    }

    /// Does the table hold nothing?
    var isEmpty: Bool { sent.isEmpty && made.isEmpty }
    /// The processes it holds a snapshot of.
    var keys: Set<ProcessKey> { Set(sent.keys).union(made.keys) }

    /// Keep a snapshot. A later one of the same process replaces it.
    ///
    /// - Parameters:
    ///   - record: The snapshot.
    ///   - isMade: Was it made from an exec or a fork? `false` for one that was sent.
    mutating func keep(_ record: ProcessSnapshotRecord, made isMade: Bool) {
        guard let key = ProcessKey(record.process_snapshot.key) else { return }
        guard isMade else {
            if sent.count >= Self.sentCapacity { sent.removeAll(keepingCapacity: true) }
            sent[key] = record
            return
        }
        if let replaced = made.updateValue(record, forKey: key) {
            bytes -= Self.weight(of: replaced)
        } else {
            order.append(key)
        }
        bytes += Self.weight(of: record)
        guard let limit else { return }
        while made.count > limit.count || bytes > limit.bytes, oldest < order.count {
            if let dropped = made.removeValue(forKey: order[oldest]) { bytes -= Self.weight(of: dropped) }
            oldest += 1
        }
        if oldest > 4_096, oldest > order.count / 2 {
            order.removeFirst(oldest)
            oldest = 0
        }
    }

    /// Take a process's snapshot out of the table: the one that was sent, or else the one that was made.
    ///
    /// - Parameter key: The process.
    /// - Returns: The snapshot, or `nil` when the table has none.
    mutating func take(_ key: ProcessKey) -> ProcessSnapshotRecord? {
        if let record = sent.removeValue(forKey: key) { return record }
        guard let record = made.removeValue(forKey: key) else { return nil }
        bytes -= Self.weight(of: record)
        return record
    }

    /// Forget a process's snapshot: a record describes it.
    ///
    /// - Parameter key: The process.
    mutating func drop(_ key: ProcessKey) {
        _ = take(key)
    }

    /// Roughly what a snapshot costs to keep, in bytes.
    ///
    /// - Parameter record: The snapshot.
    /// - Returns: Its strings' lengths and a little more.
    private static func weight(of record: ProcessSnapshotRecord) -> Int {
        let snapshot = record.process_snapshot
        return 256 + (snapshot.command_line?.utf8.count ?? 0) + (snapshot.executable?.path.utf8.count ?? 0)
            + 16 * snapshot.ancestor_keys.count
    }
}
