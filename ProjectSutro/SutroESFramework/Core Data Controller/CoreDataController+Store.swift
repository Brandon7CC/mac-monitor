//
//  CoreDataController+Store.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation
import CoreData
import OSLog
import SQLite3

extension CoreDataController {
    /// Replace the store with an empty one: every Clear's way of emptying it, and the way left when deletes fail (SQLite
    /// logs a delete before making it, which a full disk, most easily filled by a trace, has no room for, while emptying
    /// the store's files frees space). Not while an export reads the store. On `privateMOC`'s queue only, after it has let
    /// go of every object.
    ///
    /// Objects the other contexts loaded from the old store read `nil` once their context forgets them, but looking one
    /// up by ID with `object(with:)` raises an exception: readers use `existingObject(with:)`, which throws.
    ///
    /// - Returns: Whether the store was taken away, so every context must forget the objects it loaded from it. `false`
    ///   with the store as it was, if it couldn't be emptied.
    func replaceStore() -> Bool {
        let coordinator = container.persistentStoreCoordinator
        guard canSave.withLock({ $0 }), exports.withLock({ $0.isEmpty }), let url = storeURL,
              let store = coordinator.persistentStore(for: url) else { return false }
        privateMOC.reset()
        let options = store.options
        var removed = false
        coordinator.performAndWait {
            do { try coordinator.remove(store) } catch { return }
            removed = true
            do {
                try coordinator.destroyPersistentStore(at: url, type: .sqlite, options: options)
            } catch {
                CoreDataController.logger.error("Unable to empty the event store: \(error.localizedDescription)")
                /// Its events are still there: put it back, for the deletes to empty instead.
                if (try? coordinator.addPersistentStore(type: .sqlite, at: url, options: options)) != nil {
                    removed = false
                    return
                }
            }
            /// The emptied store, or (as when one can't be made at launch) one in memory.
            for location in [url, URL(fileURLWithPath: "/dev/null")] {
                guard (try? coordinator.addPersistentStore(type: .sqlite, at: location, options: options)) != nil else {
                    continue
                }
                if location == url { Self.dropUnusedIndexes(at: url, in: coordinator) }
                if coordinator.persistentStore(for: location) != nil { return }
            }
            canSave.withLock { $0 = false }
            CoreDataController.logger.fault("Unable to reopen the event store; no more events can be kept")
        }
        return removed
    }
    
    // MARK: - Unused indexes
    /// Drop the index SQLite keeps for each of `ESEventType`'s 51 relationships, which nothing looks up: a query
    /// reaches an event's payload from its `ESEventType` row, never back. Every event's row updated all 51 as it was
    /// saved, about a quarter of the time a save took (82 to 92 µs an event rather than 110 to 118, measured with this
    /// model).
    ///
    /// Core Data makes them with the store, and the store is new at every launch and every Clear, so this runs after
    /// each, with the store taken out of the coordinator so that SQLite has the only connection. It fails safe: on an
    /// error the indexes stay, which only costs the speed. Never for a store in memory.
    ///
    /// - Parameters:
    ///   - url: The store's file.
    ///   - coordinator: The coordinator the store is added to. It's added back with the same options.
    static func dropUnusedIndexes(at url: URL, in coordinator: NSPersistentStoreCoordinator) {
        guard let store = coordinator.persistentStore(for: url),
              let entity = coordinator.managedObjectModel.entitiesByName["ESEventType"] else { return }
        let table = "Z" + entity.name!.uppercased()
        let names = entity.relationshipsByName.values.filter { !$0.isToMany && $0.inverseRelationship == nil }
            .map { "\(table)_Z\($0.name.uppercased())_INDEX" }
        let options = store.options
        guard !names.isEmpty, (try? coordinator.remove(store)) != nil else { return }
        defer {
            if (try? coordinator.addPersistentStore(type: .sqlite, at: url, options: options)) == nil {
                logger.error("Unable to reopen the event store after dropping its indexes")
            }
        }
        var database: OpaquePointer?
        defer { sqlite3_close(database) }
        guard sqlite3_open_v2(url.path, &database, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK else { return }
        /// `IF EXISTS`: a future Core Data may name or make them differently. Each name carries its table's, so none
        /// can be another table's index.
        let drops = names.map { "DROP INDEX IF EXISTS \"\($0)\";" }.joined()
        if sqlite3_exec(database, "PRAGMA synchronous = OFF; BEGIN; \(drops) COMMIT;", nil, nil, nil) != SQLITE_OK {
            let message = String(cString: sqlite3_errmsg(database))
            logger.error("Unable to drop the event store's unused indexes: \(message, privacy: .public)")
            sqlite3_exec(database, "ROLLBACK;", nil, nil, nil)
        }
    }
}
