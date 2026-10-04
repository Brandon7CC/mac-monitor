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
    /// Only touched on the context's queue, through ``perform(_:completion:)``.
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
        }
        
        struct Reload {
            let total: Int
            let unified, exec: (rows: [NSManagedObjectID], selection: IndexSet, shown: Set<UUID>)
            let chart: [String: Int]
        }
        
        struct Insert {
            /// The process trees changed in a way that affects older events, so only a reload is correct.
            var lineageChanged = false
            var added = 0
            var unified: (rows: [NSManagedObjectID], inserted: IndexSet) = ([], [])
            var exec: (rows: [NSManagedObjectID], inserted: IndexSet) = ([], [])
            var chart: [String: Int] = [:]
        }
        
        private let context: NSManagedObjectContext
        /// The process trees, while "↕ Full tree" is on.
        private var lineage: ProcessLineageIndex?
        /// The audit tokens in the selected trees.
        private var tokens: Set<String>?
        
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
            func table(_ table: Snapshot.Table) throws -> (rows: [NSManagedObjectID], selection: IndexSet, shown: Set<UUID>) {
                let rows = try ids(matching: predicate(filter, for: table), sortedBy: table.sort)
                return (rows, try EventQueryModel.indexes(of: table.selection, in: rows, context: context), table.selection)
            }
            return Reload(total: try count(covered),
                          unified: try table(snapshot.unified),
                          exec: try table(snapshot.exec),
                          chart: try chartCounts(filter))
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
            
            if var index = lineage, let old = tokens {
                let fresh = index.add(try context.fetch(ProcessLineageIndex.fetchRequest(new)))
                let current = trees(snapshot.spec, in: index)
                lineage = index
                tokens = current
                /// Older events only reference processes they've already seen, so they stay in or out of the trees as long
                /// as no tree lost a process and every process that joined one is new.
                guard current.isSuperset(of: old), current.subtracting(old).isSubset(of: fresh) else {
                    result.lineageChanged = true
                    return result
                }
            }
            
            let filter = and(new, snapshot.spec.predicate(lineage: tokens))
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
            let request = ESMessage.fetchRequest()
            request.predicate = predicate(filter, for: table)
            request.sortDescriptors = table.sort
            request.returnsObjectsAsFaults = false
            let new = try context.fetch(request)
            guard !new.isEmpty else { return (table.rows, []) }
            
            let rows = table.rows
            /// Does `event` belong above `rows[index]`?
            func above(_ event: ESMessage, _ index: Int) -> Bool {
                let row = context.object(with: rows[index])
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
                while high < rows.count, !above(event, high) {
                    low = high + 1
                    high = next + step
                    step *= 2
                }
                high = min(high, rows.count)
                while low < high {
                    let middle = (low + high) / 2
                    if above(event, middle) { high = middle } else { low = middle + 1 }
                }
                merged.append(contentsOf: rows[next..<low])
                inserted.insert(merged.count)
                merged.append(event.objectID)
                next = low
            }
            merged.append(contentsOf: rows[next...])
            return (merged, inserted)
        }
        
        // MARK: Helpers
        /// - Parameters:
        ///   - spec: The filters, whose inclusion roots select the trees.
        ///   - index: The process trees.
        /// - Returns: The audit tokens in the selected trees.
        private func trees(_ spec: EventFilterSpec, in index: ProcessLineageIndex) -> Set<String> {
            spec.inclusionRoots.reduce(into: Set<String>()) { $0.formUnion(index.lineage(of: $1)) }
        }
        
        /// - Parameters:
        ///   - filter: The events that pass the filters.
        ///   - table: The table to fetch for.
        /// - Returns: `filter`, limited to `EXEC` events for the Process Execution table.
        private func predicate(_ filter: NSPredicate, for table: Snapshot.Table) -> NSPredicate {
            table.execOnly ? and(filter, NSPredicate(format: "event_type == %d", EventFilterSpec.execEventType)) : filter
        }
        
        /// - Parameter predicates: Predicates that must all hold.
        /// - Returns: Their conjunction.
        private func and(_ predicates: NSPredicate...) -> NSPredicate {
            NSCompoundPredicate(andPredicateWithSubpredicates: predicates)
        }
        
        /// - Parameter predicate: The events to count.
        /// - Returns: The number of events matching `predicate`.
        private func count(_ predicate: NSPredicate) throws -> Int {
            let request = ESMessage.fetchRequest()
            request.predicate = predicate
            return try context.count(for: request)
        }
        
        /// - Parameters:
        ///   - predicate: The events to fetch.
        ///   - sort: Their order.
        /// - Returns: The object IDs of the events matching `predicate`, in order.
        private func ids(matching predicate: NSPredicate, sortedBy sort: [NSSortDescriptor]) throws -> [NSManagedObjectID] {
            if let ordered = try textSorted(matching: predicate, sortedBy: sort) { return ordered }
            return try sqliteSorted(matching: predicate, sortedBy: sort)
        }
        
        /// Fetch the events matching `predicate` in order, sorted by SQLite.
        ///
        /// - Parameters:
        ///   - predicate: The events to fetch.
        ///   - sort: Their order.
        /// - Returns: The events' object IDs.
        private func sqliteSorted(matching predicate: NSPredicate, sortedBy sort: [NSSortDescriptor]) throws -> [NSManagedObjectID] {
            let request = NSFetchRequest<NSManagedObjectID>(entityName: "ESMessage")
            request.resultType = .managedObjectIDResultType
            request.includesPropertyValues = false
            request.predicate = predicate
            request.sortDescriptors = sort
            return try context.fetch(request)
        }
        
        /// Sort by a text column (`localizedStandardCompare:`) comparing each distinct value once, instead of letting
        /// SQLite call back into Foundation for every comparison of two rows (about 4.5 s per million rows).
        ///
        /// SQLite sorts the rows by the column's raw bytes (and the rest of the sort within each value), a grouped fetch
        /// counts each value's rows in the same order, and only the distinct values are sorted here. Wherever
        /// `localizedStandardCompare` orders the values consistently (it isn't transitive for some invisible or
        /// full-width characters) this is SQLite's own order; either way it agrees with `NSSortDescriptor.compare`, which
        /// `merge` uses.
        ///
        /// - Parameters:
        ///   - predicate: The events to fetch. Bounded by ``ESMessage/insert_batch``, so both fetches see the same rows.
        ///   - sort: Their order.
        /// - Returns: The events' object IDs, or `nil` when SQLite must sort: the first key isn't text, most values are
        ///   distinct (grouping can't win), two different values compare as equal (SQLite would interleave their rows),
        ///   or the fetches disagree.
        private func textSorted(matching predicate: NSPredicate, sortedBy sort: [NSSortDescriptor]) throws -> [NSManagedObjectID]? {
            guard let first = sort.first, let key = first.key, first.selector == #selector(NSString.localizedStandardCompare(_:)) else { return nil }
            let byBytes = NSSortDescriptor(key: key, ascending: true)
            
            let count = NSExpressionDescription()
            count.name = "count"
            count.expression = NSExpression(forFunction: "count:", arguments: [NSExpression(forKeyPath: "insert_batch")])
            count.expressionResultType = .integer64AttributeType
            let request = NSFetchRequest<NSDictionary>(entityName: "ESMessage")
            request.resultType = .dictionaryResultType
            request.predicate = predicate
            request.propertiesToFetch = [key, count]
            request.propertiesToGroupBy = [key]
            request.sortDescriptors = [byBytes]
            
            /// Each distinct value and where its rows sit in the bytewise order.
            var runs: [(value: NSString?, rows: Range<Int>)] = []
            var end = 0
            for group in try context.fetch(request) {
                let rows = (group["count"] as? NSNumber)?.intValue ?? 0
                runs.append((group[key] as? NSString, end..<end + rows))
                end += rows
            }
            /// With mostly distinct values there's little to save, and sorting them here is slower than SQLite.
            guard runs.count * 2 <= end else { return nil }
            let rows = try sqliteSorted(matching: predicate, sortedBy: [byBytes] + sort.dropFirst())
            guard rows.count == end else { return nil }
            
            /// SQLite puts NULL first ascending and last descending.
            let order: ComparisonResult = first.ascending ? .orderedAscending : .orderedDescending
            runs.sort { a, b in
                guard let x = a.value else { return b.value != nil && first.ascending }
                guard let y = b.value else { return !first.ascending }
                return x.localizedStandardCompare(y as String) == order
            }
            for (a, b) in zip(runs, runs.dropFirst()) {
                if let x = a.value, let y = b.value, x.localizedStandardCompare(y as String) == .orderedSame { return nil }
            }
            
            var ordered: [NSManagedObjectID] = []
            ordered.reserveCapacity(rows.count)
            for run in runs { ordered += rows[run.rows] }
            return ordered
        }
        
        /// - Parameter predicate: The events to count.
        /// - Returns: The events matching `predicate` per mini-chart label.
        private func chartCounts(_ predicate: NSPredicate) throws -> [String: Int] {
            let count = NSExpressionDescription()
            count.name = "count"
            count.expression = NSExpression(forFunction: "count:", arguments: [NSExpression(forKeyPath: "es_event_type")])
            count.expressionResultType = .integer64AttributeType
            
            let request = NSFetchRequest<NSDictionary>(entityName: "ESMessage")
            request.resultType = .dictionaryResultType
            request.predicate = predicate
            request.propertiesToFetch = ["es_event_type", count]
            request.propertiesToGroupBy = ["es_event_type"]
            
            return try context.fetch(request).reduce(into: [:]) { counts, row in
                guard let type = row["es_event_type"] as? String, let n = row["count"] as? Int, n > 0 else { return }
                counts[EventChartLabels.label(for: type), default: 0] += n
            }
        }
    }
}
