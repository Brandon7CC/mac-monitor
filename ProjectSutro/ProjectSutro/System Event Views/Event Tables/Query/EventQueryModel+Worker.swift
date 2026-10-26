//
//  EventQueryModel+Worker.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/4/26.
//

import AppKit
import CoreData
import SutroESFramework


// MARK: - Worker
extension EventQueryModel {
    /// The model's background half: runs fetches on its own context, one job at a time.
    ///
    /// Only touched on its context's queue: through ``perform(_:completion:)``, or by the predicate editor's preview
    /// (``EventQueryModel/preview(_:for:examples:)``) on a context of its own.
    final class Worker {
        /// What a job needs from the main thread, copied when it starts.
        struct Snapshot {
            struct Table {
                let execOnly: Bool
                let sort: [NSSortDescriptor]
                let rows: [NSManagedObjectID]
                let selection: Set<UUID>
                
                /// - Parameter query: The table to copy.
                init(query: EventTableQuery) {
                    execOnly = query.execOnly
                    sort = query.fetchSort
                    rows = query.rows
                    selection = query.selection
                }
            }
            let spec: EventFilterSpec
            /// The newest ``ESMessage/insert_batch`` received: what a reload covers.
            let through: Int64
            let unified, exec: Table
            /// Is the job still wanted? A search predicate's job stops once it isn't.
            let isCurrent: () -> Bool
        }
        
        struct Reload {
            let total: Int
            let unified, exec: (rows: [NSManagedObjectID], selection: IndexSet, shown: Set<UUID>)
            let chart: [String: Int]
            let unchecked: Unchecked
        }
        
        struct Insert {
            /// The process trees changed in a way that affects older events, or the search predicate relates events
            /// (a new one can change which older ones match), so only a reload is correct.
            var needsReload = false
            var added = 0
            var unified: (rows: [NSManagedObjectID], inserted: IndexSet) = ([], [])
            var exec: (rows: [NSManagedObjectID], inserted: IndexSet) = ([], [])
            var chart: [String: Int] = [:]
            var unchecked = Unchecked()
        }
        
        /// The events that pass a search predicate.
        struct Found {
            var ids: Set<NSManagedObjectID> = []
            /// Per mini-chart label.
            var chart: [String: Int] = [:]
            var unchecked = Unchecked()
        }
        
        /// Events loaded and checked against a search predicate at a time.
        static let batchSize = 500
        
        /// A background context of the event store, used only to read.
        let context: NSManagedObjectContext
        /// The process trees, while "↕ Full tree" is on.
        private var lineage: ProcessLineageIndex?
        /// The audit tokens in the selected trees.
        private var tokens: Set<String>?
        /// Every to-one relationship a record encodes, prefetched for a search predicate.
        private lazy var prefetch: [String] = context.persistentStoreCoordinator
            .map { ESMessage.recordPrefetchKeyPaths(in: $0.managedObjectModel) } ?? []
        
        /// - Parameter context: A background context of the event store, used only to read.
        init(context: NSManagedObjectContext) {
            self.context = context
        }
        
        /// Run a job on the context's queue and deliver its result on the main queue.
        ///
        /// - Parameters:
        ///   - work: The job.
        ///   - completion: Called on the main queue with the job's result.
        func perform<Value>(_ work: @escaping (Worker) throws -> Value, completion: @escaping (Swift.Result<Value, Error>) -> Void) {
            context.perform {
                let result = Swift.Result { try work(self) }
                /// The job only read: drop the objects it loaded.
                self.context.reset()
                DispatchQueue.main.async { completion(result) }
            }
        }
        
        // MARK: Reload
        /// Fetch every table, the total, and the chart counts from scratch.
        ///
        /// - Parameter snapshot: The filters, sorts, and batch to cover.
        /// - Returns: The results.
        func reload(_ snapshot: Snapshot) throws -> Reload {
            let covered = NSPredicate(format: "insert_batch <= %lld", snapshot.through)
            if snapshot.spec.needsLineage {
                var index = ProcessLineageIndex()
                index.add(try context.fetch(ProcessLineageIndex.fetchRequest(covered)))
                lineage = index
                tokens = trees(snapshot.spec, in: index)
            } else {
                lineage = nil
                tokens = nil
            }
            
            let filter = and(covered, snapshot.spec.predicate(lineage: tokens))
            let found = try snapshot.spec.recordPredicate.map {
                try search(filter, for: $0.copy, relatedAmong: covered, snapshot)
            }
            func table(_ table: Snapshot.Table) throws -> (rows: [NSManagedObjectID], selection: IndexSet, shown: Set<UUID>) {
                var rows = try ids(matching: predicate(filter, for: table), sortedBy: table.sort)
                if let found { rows = rows.filter(found.ids.contains) }
                return (rows, try EventQueryModel.indexes(of: table.selection, in: rows, context: context), table.selection)
            }
            return Reload(total: try count(covered),
                          unified: try table(snapshot.unified),
                          exec: try table(snapshot.exec),
                          chart: try found?.chart ?? chartCounts(filter),
                          unchecked: found?.unchecked ?? Unchecked())
        }
        
        // MARK: Insert
        /// Merge newly saved events into each table.
        ///
        /// - Parameters:
        ///   - ids: The new events.
        ///   - snapshot: The filters, sorts, and current rows.
        /// - Returns: The new rows and where they went.
        func insert(_ ids: [NSManagedObjectID], _ snapshot: Snapshot) throws -> Insert {
            let new = NSPredicate(format: "self IN %@", ids)
            var result = Insert()
            guard snapshot.spec.recordPredicate?.relatesEvents != true else {
                result.needsReload = true
                return result
            }
            
            if var index = lineage, let old = tokens {
                let fresh = index.add(try context.fetch(ProcessLineageIndex.fetchRequest(new)))
                let current = trees(snapshot.spec, in: index)
                lineage = index
                tokens = current
                /// Older events only reference processes they've already seen, so they stay in or out of the trees as long
                /// as no tree lost a process and every process that joined one is new.
                guard current.isSuperset(of: old), current.subtracting(old).isSubset(of: fresh) else {
                    result.needsReload = true
                    return result
                }
            }
            
            var filter = and(new, snapshot.spec.predicate(lineage: tokens))
            if let recordPredicate = snapshot.spec.recordPredicate {
                let found = try search(filter, for: recordPredicate.copy, relatedAmong: new, snapshot)
                filter = and(filter, NSPredicate(format: "self IN %@", Array(found.ids)))
                result.unchecked = found.unchecked
            }
            result.added = try count(new)
            result.unified = try merge(filter, into: snapshot.unified)
            result.exec = try merge(filter, into: snapshot.exec)
            result.chart = try chartCounts(filter)
            return result
        }
        
        /// Fetch the new events for one table, in its sort order, and merge them into its rows.
        ///
        /// New events usually belong at (or very near) one end, so each one gallops from where the previous one went:
        /// placing `k` events among `n` rows compares against `O(k log n)` existing rows at worst, and about `k` when
        /// they all go on top.
        ///
        /// - Parameters:
        ///   - filter: The new events that pass the filters.
        ///   - table: The table's sort and current rows.
        /// - Returns: The merged rows and the new events' positions in them.
        private func merge(_ filter: NSPredicate, into table: Snapshot.Table) throws -> (rows: [NSManagedObjectID], inserted: IndexSet) {
            let request = ESMessage.request(where: predicate(filter, for: table), sortedBy: table.sort, loaded: true)
            let new = try context.fetch(request)
            guard !new.isEmpty else { return (table.rows, []) }
            
            let rows = table.rows
            /// Does `event` belong above `rows[index]`?
            ///
            /// The row is looked up with `existingObject(with:)`, which throws for a row whose store a Clear has
            /// replaced meanwhile, where `object(with:)` raises an exception Swift can't catch. The job is then thrown
            /// away: the Clear moved its generation on.
            func above(_ event: ESMessage, _ index: Int) throws -> Bool {
                let row = try context.existingObject(with: rows[index])
                for descriptor in table.sort {
                    switch descriptor.compare(event, to: row) {
                    case .orderedAscending: return true
                    case .orderedDescending: return false
                    case .orderedSame: continue
                    }
                }
                return true
            }
            
            var merged: [NSManagedObjectID] = []
            merged.reserveCapacity(rows.count + new.count)
            var inserted = IndexSet()
            var next = 0
            for event in new {
                /// Gallop to bracket the first row `event` belongs above, then binary search the bracket.
                var low = next, step = 1, high = next
                while high < rows.count, try !above(event, high) {
                    low = high + 1
                    high = next + step
                    step *= 2
                }
                high = min(high, rows.count)
                while low < high {
                    let middle = (low + high) / 2
                    if try above(event, middle) { high = middle } else { low = middle + 1 }
                }
                merged.append(contentsOf: rows[next..<low])
                inserted.insert(merged.count)
                merged.append(event.objectID)
                next = low
            }
            merged.append(contentsOf: rows[next...])
            return (merged, inserted)
        }
        
        // MARK: Search
        /// Check each event that passes the filters against the search's predicate, on its record. It's the finding
        /// filter's and the user's predicate joined by `AND`.
        ///
        /// Core Data can't evaluate the predicate, so each event is loaded and encoded, a batch at a time: about as
        /// slow as exporting them. SQLite first narrows them by the columns the predicate's comparisons name
        /// (``StreamFilter/Predicate/storePredicate``), so only events that might match are read. A predicate that
        /// relates events first collects them from every event, filtered or not, which takes as long again.
        ///
        /// - Parameters:
        ///   - filter: The events that pass the filters.
        ///   - recordPredicate: The finding filter's and the user's predicate, parsed for this thread.
        ///   - covered: Every event its `SUBQUERY`s may relate.
        ///   - snapshot: Whether the job is still wanted.
        /// - Returns: The events whose records match, and their chart counts.
        /// - Throws: `CancellationError` once the job isn't wanted, or the fetch's error.
        private func search(_ filter: NSPredicate, for recordPredicate: StreamFilter.Predicate,
                            relatedAmong covered: NSPredicate, _ snapshot: Snapshot) throws -> Found {
            var found = Found()
            if recordPredicate.relatesEvents {
                let related = recordPredicate.relatedStorePredicate.map { and(covered, $0) } ?? covered
                try forEachEvent(matching: related, isCurrent: snapshot.isCurrent) { message in
                    do { try recordPredicate.collect(message) } catch { found.unchecked.add(error) }
                }
            }
            let candidates = recordPredicate.storePredicate.map { and(filter, $0) } ?? filter
            try forEachEvent(matching: candidates, isCurrent: snapshot.isCurrent) { message in
                do {
                    guard try recordPredicate.evaluate(on: message) else { return }
                    found.ids.insert(message.objectID)
                    guard let type = message.es_event_type else { return }
                    found.chart[EventChartLabels.label(for: type), default: 0] += 1
                } catch {
                    found.unchecked.add(error)
                }
            }
            return found
        }
        
        /// Load each event matching a predicate, with what its record encodes, a batch at a time.
        ///
        /// - Parameters:
        ///   - predicate: The events, or `nil` for every one.
        ///   - sort: Their order.
        ///   - isCurrent: Is the job still wanted?
        ///   - body: Called with each event, on the context's queue.
        /// - Throws: `CancellationError` once the job isn't wanted, or the fetch's error.
        func forEachEvent(matching predicate: NSPredicate?, sortedBy sort: [NSSortDescriptor] = [],
                          isCurrent: () -> Bool, _ body: (ESMessage) throws -> Void) throws {
            let ids = try sqliteSorted(matching: predicate, sortedBy: sort)
            for start in stride(from: 0, to: ids.count, by: Self.batchSize) {
                try autoreleasepool {
                    let batch = Array(ids[start..<min(start + Self.batchSize, ids.count)])
                    let request = ESMessage.request(where: NSPredicate(format: "self IN %@", batch), sortedBy: sort,
                                                    loaded: true)
                    request.relationshipKeyPathsForPrefetching = prefetch
                    for message in try context.fetch(request) {
                        /// Each event can take a while: a `MATCHES` has up to `BoundedMatches.limit` for each value.
                        guard isCurrent() else { throw CancellationError() }
                        try body(message)
                    }
                    context.reset()
                }
            }
        }
    }
}
