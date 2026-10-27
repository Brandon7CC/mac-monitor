//
//  EventQueryModel+Selection.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import CoreData
import SutroESFramework


// MARK: - Selection
extension EventQueryModel {
    /// Find the events `rows` hold, off the main thread.
    ///
    /// - Parameters:
    ///   - rows: Rows of a table.
    ///   - completion: Called on the main thread with the events' IDs.
    func eventIDs(of rows: [NSManagedObjectID], completion: @escaping (Set<UUID>) -> Void) {
        mapSelection({ try Self.eventIDs(of: rows, context: $0) }, completion: completion)
    }
    
    /// Find which of `rows` hold the events `ids`, off the main thread.
    ///
    /// - Parameters:
    ///   - ids: Event IDs.
    ///   - rows: Rows of a table.
    ///   - completion: Called on the main thread with the indexes of the rows holding those events.
    func indexes(of ids: Set<UUID>, in rows: [NSManagedObjectID], completion: @escaping (IndexSet) -> Void) {
        mapSelection({ try Self.indexes(of: ids, in: rows, context: $0) }, completion: completion)
    }
    
    /// Run selection work on ``selectionContext`` (not the worker, whose reloads can take a while).
    ///
    /// - Parameters:
    ///   - work: Reads from the context it's given.
    ///   - completion: Called on the main thread with the result, or an empty one if the work failed.
    private func mapSelection<Value: SetAlgebra>(_ work: @escaping (NSManagedObjectContext) throws -> Value,
                                                 completion: @escaping (Value) -> Void) {
        let context = selectionContext
        context.perform {
            let value = (try? work(context)) ?? Value()
            context.reset()
            DispatchQueue.main.async { completion(value) }
        }
    }
    
    /// - Parameters:
    ///   - rows: Rows of a table.
    ///   - context: The context to fetch with. Call on its queue.
    /// - Returns: The IDs of the events in `rows`.
    static func eventIDs(of rows: [NSManagedObjectID], context: NSManagedObjectContext) throws -> Set<UUID> {
        guard !rows.isEmpty else { return [] }
        let request = ESMessage.request(NSDictionary.self, where: NSPredicate(format: "self IN %@", rows))
        request.propertiesToFetch = ["id"]
        return Set(try context.fetch(request).compactMap { $0["id"] as? UUID })
    }
    
    /// - Parameters:
    ///   - ids: Event IDs.
    ///   - rows: Rows of a table.
    ///   - context: The context to fetch with. Call on its queue.
    /// - Returns: The indexes of the rows holding the events `ids` (looked up by the indexed `id`, then one pass over
    ///   `rows`).
    static func indexes(of ids: Set<UUID>, in rows: [NSManagedObjectID],
                        context: NSManagedObjectContext) throws -> IndexSet {
        guard !ids.isEmpty, !rows.isEmpty else { return [] }
        let request = ESMessage.request(NSManagedObjectID.self, where: NSPredicate(format: "id IN %@", Array(ids)))
        let wanted = Set(try context.fetch(request))
        guard !wanted.isEmpty else { return [] }
        return IndexSet(rows.indices.lazy.filter { wanted.contains(rows[$0]) })
    }
}
