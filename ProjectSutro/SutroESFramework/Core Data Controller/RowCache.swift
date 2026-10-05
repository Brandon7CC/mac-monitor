//
//  RowCache.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/2/26.
//

import Foundation
import CoreData


// MARK: - Row cache
/// Hands out one stored row per distinct value, so rows that only repeat a value (a process's `ESProcess`, its audit
/// tokens, its executable) are stored once instead of once per event (#84).
///
/// Rows inserted since the last save are kept as objects, because their object IDs are still temporary. After a save
/// they're kept by permanent object ID and handed out as faults, which cost no I/O when they're only attached to a new
/// object with ``NSManagedObject/attach(_:to:)``.
///
/// Bounded: the IDs live in two generations of up to `capacity` values each. When the newer one fills up the older one
/// is dropped, and a value found in the older one moves to the newer one, so values still in use stay. Forgetting a
/// value only costs one more row for it.
///
/// Only used on the queue of the context that inserts events.
final class RowCache<Key: Hashable> {
    /// Rows inserted since the last save.
    private var unsaved: [Key: NSManagedObject] = [:]
    /// Saved rows, newer and older generation.
    private var recent: [Key: NSManagedObjectID] = [:]
    private var older: [Key: NSManagedObjectID] = [:]
    private let capacity: Int
    
    /// - Parameter capacity: The values each generation holds.
    init(capacity: Int) {
        self.capacity = capacity
    }
    
    /// The row for `key`: one handed out before, or a new one from `make`.
    ///
    /// - Parameters:
    ///   - key: The row's value, without the random IDs the value types carry.
    ///   - context: The context the row is used in. Must be the one `make` inserts into.
    ///   - make: Inserts a new row for `key`.
    /// - Returns: The row, which may be a fault.
    func row<Row: NSManagedObject>(for key: Key, in context: NSManagedObjectContext, make: () -> Row) -> Row {
        if let row = unsaved[key] as? Row { return row }
        var saved = recent[key]
        if saved == nil, let id = older.removeValue(forKey: key) {
            recent[key] = id
            saved = id
        }
        if let saved, let row = context.object(with: saved) as? Row { return row }
        let row = make()
        unsaved[key] = row
        return row
    }
    
    /// Keep the rows just saved, by their now permanent IDs. Call after a successful save, before the context is reset.
    func didSave() {
        for (key, row) in unsaved where !row.objectID.isTemporaryID { recent[key] = row.objectID }
        unsaved.removeAll(keepingCapacity: true)
        if recent.count > capacity {
            older = recent
            recent = [:]
        }
    }
    
    /// Forget every row: after a Clear (the rows are gone) and after a failed save (the rows not yet saved may be rolled
    /// back, and are saved, if at all, only with the events already holding them).
    func forget() {
        unsaved = [:]
        recent = [:]
        older = [:]
    }
}


// MARK: - Event row caches
/// The row caches of the context that inserts events, kept in its `userInfo` so the entities' initializers find them
/// however deep they're called. A context without them (any other) inserts a new row every time, as before.
///
/// Only used on that context's queue.
final class EventRowCaches {
    static let userInfoKey = "com.swiftlydetecting.SutroESFramework.EventRowCaches"
    
    /// `ESProcess` rows, with their audit tokens, executable, tty, and stats.
    let processes = RowCache<ProcessRowKey>(capacity: 2_048)
    /// `ESFile` rows, with their `ESStat`.
    let files = RowCache<File>(capacity: 2_048)
    /// `ESAuditToken` rows.
    let tokens = RowCache<AuditToken>(capacity: 4_096)
    
    /// The row for a value, shared when `context` has row caches.
    ///
    /// - Parameters:
    ///   - cache: Which cache to use.
    ///   - key: The value, without its random IDs. Only computed when `context` has row caches.
    ///   - context: The context to insert into.
    ///   - make: Inserts a new row.
    /// - Returns: The row, which may be a fault.
    static func row<Key, Row: NSManagedObject>(_ cache: KeyPath<EventRowCaches, RowCache<Key>>, for key: @autoclosure () -> Key,
                                               in context: NSManagedObjectContext, make: () -> Row) -> Row {
        guard let caches = context.userInfo[userInfoKey] as? EventRowCaches else { return make() }
        return caches[keyPath: cache].row(for: key(), in: context, make: make)
    }
    
    /// See ``RowCache/didSave()``.
    func didSave() {
        processes.didSave()
        files.didSave()
        tokens.didSave()
    }
    
    /// See ``RowCache/forget()``.
    func forget() {
        processes.forget()
        files.forget()
        tokens.forget()
    }
}

/// What an `ESProcess` row stores: the process without its random IDs, and the message version (it decides whether
/// `cs_validation_category` is stored).
struct ProcessRowKey: Hashable {
    let version: Int
    let process: Process
}


// MARK: - Attaching shared rows
extension NSManagedObject {
    /// Point this newly inserted object's to-one relationship `key` at `row`, which may be shared and already saved.
    ///
    /// The relationship's setter would fire `row`'s fault and mark it updated (one `SELECT` and one `UPDATE` per shared
    /// row per save), even though the relationships it's used for have no inverse. A primitive value is stored with the
    /// new object all the same, but it never updates an inverse, so it's only for relationships without one.
    ///
    /// - Parameters:
    ///   - row: The destination.
    ///   - key: The relationship, as `#keyPath(Entity.relationship)`.
    func attach(_ row: NSManagedObject, to key: String) {
        setPrimitiveValue(row, forKey: key)
    }
}


// MARK: - Values without their random IDs
/// The `id` every value gets in a row cache key, so equal values have equal keys.
private let zeroID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

extension AuditToken {
    /// This token with its random `id` zeroed.
    var rowKey: AuditToken { var token = self; token.id = zeroID; return token }
    
    /// The token as ``ESAuditToken/toString()`` formats it (also what `ESProcess` stores as `*_audit_token_string`).
    func toString() -> String {
        "pid:\(pid), euid:\(euid), ruid:\(ruid), rgid:\(rgid), egid:\(egid), asid:\(asid), auid:\(auid), pidversion:\(pidversion)"
    }
}

extension Stat {
    /// This stat with its random IDs zeroed.
    var rowKey: Stat {
        var stat = self
        stat.id = zeroID
        stat.st_atimespec.id = zeroID
        stat.st_mtimespec.id = zeroID
        stat.st_ctimespec.id = zeroID
        stat.st_birthtimespec.id = zeroID
        return stat
    }
}

extension File {
    /// This file with its random IDs zeroed.
    var rowKey: File { var file = self; file.id = zeroID; file.stat = file.stat.rowKey; return file }
}

extension Process {
    /// This process with its random IDs (and its tokens', executable's, and tty's) zeroed.
    var rowKey: Process {
        var process = self
        process.id = zeroID
        process.start_time.id = zeroID
        process.audit_token = process.audit_token?.rowKey
        process.parent_audit_token = process.parent_audit_token?.rowKey
        process.responsible_audit_token = process.responsible_audit_token?.rowKey
        process.executable = process.executable?.rowKey
        process.tty = process.tty?.rowKey
        return process
    }
}
