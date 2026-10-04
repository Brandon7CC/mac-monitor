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
