//
//  EventQueryModel+WorkerFetches.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/26/26.
//

import CoreData
import SutroESFramework


// MARK: - Helpers
extension EventQueryModel.Worker {
    /// - Parameters:
    ///   - spec: The filters, whose inclusion roots select the trees.
    ///   - index: The process trees.
    /// - Returns: The audit tokens in the selected trees.
    func trees(_ spec: EventFilterSpec, in index: ProcessLineageIndex) -> Set<String> {
        spec.inclusionRoots.reduce(into: Set<String>()) { $0.formUnion(index.lineage(of: $1)) }
    }
    
    /// - Parameters:
    ///   - filter: The events that pass the filters.
    ///   - table: The table to fetch for.
    /// - Returns: `filter`, limited to `EXEC` events for the Process Execution table.
    func predicate(_ filter: NSPredicate, for table: Snapshot.Table) -> NSPredicate {
        table.execOnly ? and(filter, NSPredicate(format: "event_type == %d", ESMessage.execEventType)) : filter
    }
    
    /// - Parameter predicates: Predicates that must all hold.
    /// - Returns: Their conjunction.
    func and(_ predicates: NSPredicate...) -> NSPredicate {
        NSCompoundPredicate(andPredicateWithSubpredicates: predicates)
    }
    
    /// - Parameter predicate: The events to count.
    /// - Returns: The number of events matching `predicate`.
    func count(_ predicate: NSPredicate) throws -> Int {
        try context.count(for: ESMessage.request(where: predicate))
    }
    
    /// - Parameters:
    ///   - predicate: The events to fetch.
    ///   - sort: Their order.
    /// - Returns: The object IDs of the events matching `predicate`, in order.
    func ids(matching predicate: NSPredicate, sortedBy sort: [NSSortDescriptor]) throws -> [NSManagedObjectID] {
        if let ordered = try textSorted(matching: predicate, sortedBy: sort) { return ordered }
        return try sqliteSorted(matching: predicate, sortedBy: sort)
    }
    
    /// Fetch the events matching `predicate` in order, sorted by SQLite.
    ///
    /// - Parameters:
    ///   - predicate: The events to fetch, or `nil` for every one.
    ///   - sort: Their order.
    /// - Returns: The events' object IDs.
    func sqliteSorted(matching predicate: NSPredicate?,
                      sortedBy sort: [NSSortDescriptor]) throws -> [NSManagedObjectID] {
        let request = ESMessage.request(NSManagedObjectID.self, where: predicate, sortedBy: sort)
        request.includesPropertyValues = false
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
    private func textSorted(matching predicate: NSPredicate,
                            sortedBy sort: [NSSortDescriptor]) throws -> [NSManagedObjectID]? {
        guard let first = sort.first, let key = first.key,
              first.selector == #selector(NSString.localizedStandardCompare(_:)) else { return nil }
        let byBytes = NSSortDescriptor(key: key, ascending: true)
        
        let count = NSExpressionDescription()
        count.name = "count"
        count.expression = NSExpression(forFunction: "count:", arguments: [NSExpression(forKeyPath: "insert_batch")])
        count.expressionResultType = .integer64AttributeType
        let request = ESMessage.request(NSDictionary.self, where: predicate, sortedBy: [byBytes])
        request.propertiesToFetch = [key, count]
        request.propertiesToGroupBy = [key]
        
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
    func chartCounts(_ predicate: NSPredicate) throws -> [String: Int] {
        let count = NSExpressionDescription()
        count.name = "count"
        count.expression = NSExpression(forFunction: "count:", arguments: [NSExpression(forKeyPath: "es_event_type")])
        count.expressionResultType = .integer64AttributeType
        
        let request = ESMessage.request(NSDictionary.self, where: predicate)
        request.propertiesToFetch = ["es_event_type", count]
        request.propertiesToGroupBy = ["es_event_type"]
        
        return try context.fetch(request).reduce(into: [:]) { counts, row in
            guard let type = row["es_event_type"] as? String, let n = row["count"] as? Int, n > 0 else { return }
            counts[EventChartLabels.label(for: type), default: 0] += n
        }
    }
}
