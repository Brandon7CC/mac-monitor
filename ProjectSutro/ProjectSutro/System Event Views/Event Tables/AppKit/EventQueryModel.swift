//
//  EventQueryModel.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/26.
//

import AppKit
import CoreData
import OSLog
import SutroESFramework


// MARK: - Table query
/// The rows of one AppKit event table: the object IDs of the events that pass the filters, in the table's sort order.
///
/// Only object IDs are kept. The table asks the view context for the few events on screen, so a table costs about the
/// same whether it holds a hundred events or millions. ``EventQueryModel`` fills it from a background context and pushes
/// each change straight to the table view, never through SwiftUI (which would diff every row on every change).
///
/// Main thread only.
final class EventTableQuery {
    /// Newest first.
    static let defaultSort = [NSSortDescriptor(key: "message_darwin_time", ascending: false)]
    
    /// Only `EXEC` events (the Process Execution table)?
    let execOnly: Bool
    /// The sort chosen in the table's header. Fetches add `mach_time` descending to break ties.
    var sortDescriptors: [NSSortDescriptor] = defaultSort
    /// The columns' order, widths, and visibility, kept so a table rebuilt by SwiftUI (e.g. the mini-chart toggle) looks
    /// the same. Empty until the table's columns first change.
    var columnLayout: [ColumnLayout] = []
    /// The rows, top to bottom.
    private(set) var rows: [NSManagedObjectID] = []
    /// Bumped whenever `rows` changes, so work done against older rows can be recognized.
    private(set) var version = 0
    /// The table showing these rows, if one is on screen.
    weak var tableView: NSTableView?
    
    /// The rows each insert added since the rows were last replaced, so row indexes found earlier can be brought up to
    /// date (see ``current(_:from:)``) instead of looked up again.
    private var insertions: [(version: Int, indexes: IndexSet)] = []
    /// The oldest version ``current(_:from:)`` can bring up to date.
    private var oldestCurrentable = 0
    
    /// The events the table should show selected: the shared selection, kept current by the table. Reloads select them
    /// again in the new rows.
    var selection: Set<UUID> = []
    /// The selection the table's selected rows reflect. Lags `selection` while a new one is being found in the rows.
    private(set) var shownSelection: Set<UUID> = []
    /// Set while the rows or their selection are being changed in code, so the table doesn't take the change for the
    /// user's.
    private(set) var isUpdating = false
    /// Called after the rows are replaced, so the table can check its selection is still current.
    var onReplace: (() -> Void)?
    
    /// - Parameter execOnly: Only show `EXEC` events.
    init(execOnly: Bool) {
        self.execOnly = execOnly
    }
    
    /// The full fetch sort: the header's sort, then `mach_time` descending.
    var fetchSort: [NSSortDescriptor] { sortDescriptors + [NSSortDescriptor(key: "mach_time", ascending: false)] }
    
    /// Replace every row.
    ///
    /// - Parameters:
    ///   - rows: The new rows.
    ///   - indexes: The rows to select.
    ///   - shown: The selection those rows reflect.
    func replace(with rows: [NSManagedObjectID], selecting indexes: IndexSet = [], showing shown: Set<UUID>) {
        self.rows = rows
        version += 1
        insertions = []
        oldestCurrentable = version
        updating { tableView?.reloadData() }
        select(indexes, showing: shown)
        onReplace?()
    }
    
    /// Select rows to reflect a selection.
    ///
    /// - Parameters:
    ///   - indexes: The rows holding the selected events.
    ///   - shown: The selection they reflect.
    func select(_ indexes: IndexSet, showing shown: Set<UUID>) {
        shownSelection = shown
        updating { tableView?.selectRowIndexes(indexes, byExtendingSelection: false) }
    }
    
    /// The user selected rows holding the events `ids`.
    ///
    /// - Parameter ids: The selected events.
    func userSelected(_ ids: Set<UUID>) {
        selection = ids
        shownSelection = ids
    }
    
    /// - Parameter change: Changes the table in code.
    private func updating(_ change: () -> Void) {
        isUpdating = true
        defer { isUpdating = false }
        change()
    }
    
    /// Insert rows. The table keeps its other rows' views and shifts the selection to match.
    ///
    /// - Parameters:
    ///   - rows: The rows after the insert.
    ///   - indexes: Where the new rows are in `rows`.
    func insert(_ rows: [NSManagedObjectID], at indexes: IndexSet) {
        guard !indexes.isEmpty else { return }
        version += 1
        insertions.append((version, indexes))
        /// Keep a bounded history: indexes older than it are looked up again.
        if insertions.count > 64 { oldestCurrentable = insertions.removeFirst().version }
        /// A table that hasn't counted the current rows yet (e.g. just created) can only be reloaded.
        guard let tableView, tableView.numberOfRows == self.rows.count else {
            self.rows = rows
            updating { tableView?.reloadData() }
            return
        }
        updating {
            tableView.beginUpdates()
            self.rows = rows
            tableView.insertRows(at: indexes, withAnimation: [])
            tableView.endUpdates()
        }
    }
    
    /// Bring row indexes found in an older version of the rows up to date, shifting them past every row inserted since,
    /// the same way `insertRows(at:withAnimation:)` shifts a table's selection.
    ///
    /// - Parameters:
    ///   - indexes: Indexes into the rows as they were at `version`.
    ///   - version: The ``version`` they were found in.
    /// - Returns: The same rows' indexes now, or `nil` if the rows were replaced since (look them up again).
    func current(_ indexes: IndexSet, from version: Int) -> IndexSet? {
        guard version >= oldestCurrentable else { return nil }
        var result = indexes
        for insertion in insertions where insertion.version > version {
            /// Insert positions are in final coordinates, so shifting at each in ascending order lands every row right.
            insertion.indexes.forEach { result.shift(startingAt: $0, by: 1) }
        }
        return result
    }
}


// MARK: - Column layout
/// One column's place in a table's layout, saved so the columns look the same when the table is rebuilt or its window
/// restored. The layout is kept in scene storage.
struct ColumnLayout: Codable, Equatable {
    /// The column's identifier (its title).
    let id: String
    let width: CGFloat
    let isHidden: Bool
    
    /// - Parameter string: A layout from ``encode(_:)``.
    /// - Returns: The layout, or none if `string` is empty or unreadable.
    static func decode(_ string: String) -> [ColumnLayout] {
        (try? JSONDecoder().decode([ColumnLayout].self, from: Data(string.utf8))) ?? []
    }
    
    /// - Parameter layout: Every column, in order.
    /// - Returns: The layout as a string for scene storage.
    static func encode(_ layout: [ColumnLayout]) -> String {
        (try? JSONEncoder().encode(layout)).flatMap { String(data: $0, encoding: .utf8) } ?? ""
    }
}


// MARK: - Query model
/// Keeps the AppKit event tables, the event counts, and the mini-chart up to date with the event store.
///
/// Fetching every event into the view context and filtering, sorting, counting, and charting them on the main thread on
/// every save (the SwiftUI tables of v2.1) stops scaling around a million events (#84). This model does that work with
/// Core Data on a background context instead, and keeps only what the screen needs:
///
/// - **Reload** (filters, search, sort, or Clear changed): fetch each table's rows as object IDs, sorted and filtered by
///   SQLite, plus the totals and per-event-type counts.
/// - **Insert** (``CoreDataController/eventsInserted``): fetch just the new events that pass the filters and merge them
///   into each table's rows.
///
/// One job runs at a time. Changes that arrive meanwhile are coalesced into the next job, so typing in the search field or
/// a burst of events never queues up work. A reload covers every batch saved up to the newest one received
/// (``ESMessage/insert_batch``), so no event is shown twice or missed.
///
/// Main thread only. Inactive (no observers, no work) until ``activate(spec:)``.
final class EventQueryModel: ObservableObject {
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "EventQueryModel")
    
    /// Every event in the store.
    @Published private(set) var totalCount = 0
    /// The events that pass the filters and search (the unified table's rows).
    @Published private(set) var filteredCount = 0
    /// Filtered events per mini-chart label (see ``EventChartLabels``).
    @Published private(set) var chartCounts: [String: Int] = [:]
    
    /// The "System Security Unified" table.
    let unified = EventTableQuery(execOnly: false)
    /// The "Process Execution" table.
    let exec = EventTableQuery(execOnly: true)
    
    private let controller: CoreDataController
    private let worker: Worker
    /// Maps selections between rows and event IDs.
    private lazy var selectionContext = controller.container.newBackgroundContext()
    private var observers: [NSObjectProtocol] = []
    
    private var spec: EventFilterSpec?
    /// Bumped whenever results already being computed should be thrown away (a reload is due, or Clear).
    private var generation = 0
    private var isWorking = false
    private var needsReload = false
    /// Events saved since the last job started, waiting to be merged in.
    private var pendingInserts: [NSManagedObjectID] = []
    /// The newest ``ESMessage/insert_batch`` covered: received, or saved before the model started following the store.
    private var lastBatch: Int64 = 0
    /// After a failed job, wait until then before trying again, doubling the wait on each failure in a row.
    private var retryAt: Date = .distantPast
    private var retryDelay: TimeInterval = 0
    
    /// The context the tables read the events on screen from.
    var viewContext: NSManagedObjectContext { controller.container.viewContext }
    
    /// - Parameter controller: The event store.
    init(controller: CoreDataController = .shared) {
        self.controller = controller
        self.worker = Worker(context: controller.container.newBackgroundContext())
    }
    
    deinit {
        observers.forEach { NotificationCenter.default.removeObserver($0) }
    }
    
    // MARK: Lifecycle
    /// Start following the event store and load every table.
    ///
    /// Also stops the view context from merging every save: nothing on screen needs it, and merging faults in every new
    /// event on the main thread.
    ///
    /// - Parameter spec: The filters to apply.
    func activate(spec: EventFilterSpec) {
        guard observers.isEmpty else { return update(spec: spec) }
        viewContext.automaticallyMergesChangesFromParent = false
        let center = NotificationCenter.default
        observers = [
            center.addObserver(forName: CoreDataController.eventsInserted, object: controller, queue: nil) { [weak self] note in
                guard let ids = note.userInfo?[CoreDataController.insertedObjectIDsKey] as? [NSManagedObjectID],
                      let batch = note.userInfo?[CoreDataController.insertBatchKey] as? Int64 else { return }
                DispatchQueue.main.async { self?.received(ids, batch: batch) }
            },
            /// Posted on the main thread, right before the delete: handle it synchronously.
            center.addObserver(forName: CoreDataController.eventsWillClear, object: controller, queue: nil) { [weak self] _ in
                if Thread.isMainThread {
                    self?.willClear()
                } else {
                    DispatchQueue.main.async { self?.willClear() }
                }
            },
            /// The delete finished: load whatever has been saved since.
            center.addObserver(forName: CoreDataController.eventsDidClear, object: controller, queue: .main) { [weak self] _ in
                self?.pump()
            },
        ]
        /// Batches saved before now were never announced to this model. The reload below covers them; their
        /// notifications still in flight are dropped by `received`.
        lastBatch = max(lastBatch, controller.lastInsertBatch)
        self.spec = spec
        reload()
    }
    
    /// Apply new filters or search text.
    ///
    /// - Parameter spec: The filters to apply.
    func update(spec: EventFilterSpec) {
        guard spec != self.spec else { return }
        self.spec = spec
        reload()
    }
    
    /// Refetch everything (e.g. after a table's sort changed).
    func reload() {
        generation += 1
        needsReload = true
        pump()
    }
    
    // MARK: Events
    /// A batch of events was saved.
    ///
    /// - Parameters:
    ///   - ids: The new events.
    ///   - batch: Their ``ESMessage/insert_batch``.
    private func received(_ ids: [NSManagedObjectID], batch: Int64) {
        /// Batches are announced in order, so one at or below `lastBatch` is already covered by a reload.
        guard !observers.isEmpty, batch > lastBatch else { return }
        lastBatch = batch
        pendingInserts += ids
        pump()
    }
    
    /// Events are about to be deleted: drop every row now, before the table can draw a deleted event.
    ///
    /// No job starts until the delete finishes (``CoreDataController/eventsDidClear``); then a reload loads what was saved
    /// after it.
    private func willClear() {
        generation += 1
        needsReload = true
        pendingInserts = []
        for query in [unified, exec] { query.replace(with: [], showing: query.selection) }
        totalCount = 0
        filteredCount = 0
        chartCounts = [:]
    }
    
    // MARK: Selection
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
    private func mapSelection<Value: SetAlgebra>(_ work: @escaping (NSManagedObjectContext) throws -> Value, completion: @escaping (Value) -> Void) {
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
        let request = NSFetchRequest<NSDictionary>(entityName: "ESMessage")
        request.resultType = .dictionaryResultType
        request.propertiesToFetch = ["id"]
        request.predicate = NSPredicate(format: "self IN %@", rows)
        return Set(try context.fetch(request).compactMap { $0["id"] as? UUID })
    }
    
    /// - Parameters:
    ///   - ids: Event IDs.
    ///   - rows: Rows of a table.
    ///   - context: The context to fetch with. Call on its queue.
    /// - Returns: The indexes of the rows holding the events `ids` (looked up by the indexed `id`, then one pass over
    ///   `rows`).
    static func indexes(of ids: Set<UUID>, in rows: [NSManagedObjectID], context: NSManagedObjectContext) throws -> IndexSet {
        guard !ids.isEmpty, !rows.isEmpty else { return [] }
        let request = NSFetchRequest<NSManagedObjectID>(entityName: "ESMessage")
        request.resultType = .managedObjectIDResultType
        request.predicate = NSPredicate(format: "id IN %@", Array(ids))
        let wanted = Set(try context.fetch(request))
        guard !wanted.isEmpty else { return [] }
        return IndexSet(rows.indices.lazy.filter { wanted.contains(rows[$0]) })
    }
    
    // MARK: Jobs
    /// Start the next job, unless one is running.
    private func pump() {
        guard !observers.isEmpty, !isWorking, !controller.isClearing, Date() >= retryAt, let spec else { return }
        let snapshot = Worker.Snapshot(spec: spec, through: lastBatch,
                                       unified: .init(query: unified), exec: .init(query: exec))
        if needsReload {
            /// A reload covers every batch received so far.
            needsReload = false
            pendingInserts = []
            run({ try $0.reload(snapshot) }, then: apply(reload:))
        } else if !pendingInserts.isEmpty {
            let ids = pendingInserts
            pendingInserts = []
            run({ try $0.insert(ids, snapshot) }, then: apply(insert:))
        }
    }
    
    /// Run `work` on the worker's queue, then `apply` its result here, unless the generation moved on meanwhile.
    ///
    /// - Parameters:
    ///   - work: The job.
    ///   - apply: Applies the job's result on the main thread.
    private func run<Value>(_ work: @escaping (Worker) throws -> Value, then apply: @escaping (Value) -> Void) {
        isWorking = true
        let started = generation
        worker.perform(work) { [weak self] result in
            guard let self else { return }
            self.isWorking = false
            switch result {
            case .success(let value):
                self.retryDelay = 0
                if started == self.generation { apply(value) }
            case .failure(let error):
                Self.logger.error("Unable to query events: \(error.localizedDescription, privacy: .public)")
                /// Try again from scratch (unless a reload is already due) after a growing pause, so a lasting failure
                /// (e.g. a full disk) doesn't keep a core busy.
                if started == self.generation { self.needsReload = true }
                self.retryDelay = min(max(self.retryDelay * 2, 0.5), 8)
                self.retryAt = Date().addingTimeInterval(self.retryDelay)
                DispatchQueue.main.asyncAfter(deadline: .now() + self.retryDelay) { [weak self] in self?.pump() }
            }
            self.pump()
        }
    }
    
    /// - Parameter result: A finished reload.
    private func apply(reload result: Worker.Reload) {
        unified.replace(with: result.unified.rows, selecting: result.unified.selection, showing: result.unified.shown)
        exec.replace(with: result.exec.rows, selecting: result.exec.selection, showing: result.exec.shown)
        totalCount = result.total
        filteredCount = unified.rows.count
        chartCounts = result.chart
    }
    
    /// - Parameter result: A finished insert.
    private func apply(insert result: Worker.Insert) {
        guard !result.lineageChanged else { return reload() }
        unified.insert(result.unified.rows, at: result.unified.inserted)
        exec.insert(result.exec.rows, at: result.exec.inserted)
        totalCount += result.added
        filteredCount = unified.rows.count
        if !result.chart.isEmpty { chartCounts.merge(result.chart, uniquingKeysWith: +) }
    }
}


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
