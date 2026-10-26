//
//  TelemetryExporter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/2/26.
//

import Foundation
import CoreData
import os


// MARK: - Telemetry exporter
/// Streams events from the event store to a file a batch at a time, on its own background context.
///
/// Exporting used to fetch and encode the whole trace at once: about 22 KB of memory per event, on the context that
/// inserts events (so recording stalled until the export finished) or on the main thread (#84). This keeps memory flat
/// and leaves both free, whatever the trace's size.
///
/// The file is byte for byte what the old exports wrote: each event as ``ProcessHelpers/eventToJSON(value:)`` (JSONL) or
/// ``ProcessHelpers/eventToPrettyJSON(value:)``, joined by "\n" with no trailing newline, and saved atomically. Since
/// 3.0.0 each event also carries its telemetry version
/// (``TelemetrySchema/versionKey``), which ``ESMessage`` encodes.
///
/// The context is pinned to the store as it was when the export started (``pin()``), so events cleared meanwhile still
/// export. While pinned, SQLite can't fold its write-ahead log back into the store, so the log grows with whatever changes
/// during the export (measured: about 4 KB per event cleared, plus each inserted event's size) until the export finishes.
///
/// A large trace takes a while to encode, so the export reports how many of its events it has written, and fetches and
/// encodes several batches at once, each on its own context pinned to the same snapshot (``Worker``), writing them in
/// file order. JSONL records are written by ``StreamingJSONEncoder`` where it sorts keys as this Mac's `JSONEncoder`
/// does, so they stay byte for byte what ``ProcessHelpers/eventToJSON(value:)`` writes. Measured on an M1 Max with a
/// recording's events (JSONL): 4,800 events a second one batch at a time through `JSONEncoder`, 7,000 through the
/// streaming encoder, and 11,000 to 12,900 with two workers, so 5.3 million events take 7 to 8 minutes, not 18.
public final class TelemetryExporter {
    /// How far an export has got, once it knows which events it writes.
    public struct Progress: Equatable {
        /// Events written so far.
        public let written: Int
        /// Events the file will hold.
        public let total: Int
        /// `written` over `total`, from 0 to 1.
        public var fraction: Double { total > 0 ? min(1, Double(written) / Double(total)) : 1 }
        
        /// - Parameters:
        ///   - written: Events written so far.
        ///   - total: Events the file will hold.
        public init(written: Int, total: Int) {
            self.written = written
            self.total = total
        }
    }
    
    /// Events fetched and encoded at a time, by each worker.
    static let batchSize = 500
    /// Selected event IDs looked up per fetch.
    static let lookupSize = 10_000
    /// Batches fetched and encoded at once: two, given two cores. One worker's fetch overlaps another's encoding, but
    /// fetches wait for each other on the store's coordinator, so a third worker or more measured no faster (12,900
    /// events a second with two, four or six, whatever the connection pool's size).
    static var defaultWorkers: Int { min(2, ProcessInfo.processInfo.activeProcessorCount) }
    
    /// Chooses the events, and writes the file.
    private let context: NSManagedObjectContext
    /// Fetch and encode the batches, each on its own context.
    private let workers: [Worker]
    private let pretty: Bool
    /// Every to-one relationship an event encodes, fetched along with each batch.
    private let prefetch: [String]
    private let cancelled = OSAllocatedUnfairLock(initialState: false)
    /// The shortest time between progress reports while writing, in nanoseconds.
    private let reportInterval: UInt64
    
    /// - Parameters:
    ///   - container: The event store.
    ///   - pretty: Pretty-printed JSON (`true`) or JSONL (`false`).
    ///   - reportInterval: The shortest time between progress reports while writing: a tenth of a second, as opening a
    ///     trace reports, or none, so tests see a report per batch.
    ///   - workers: Batches fetched and encoded at once.
    init(container: NSPersistentContainer, pretty: Bool, reportInterval: UInt64 = 100_000_000,
         workers: Int = TelemetryExporter.defaultWorkers) {
        context = container.newBackgroundContext()
        self.pretty = pretty
        self.reportInterval = reportInterval
        prefetch = ESMessage.recordPrefetchKeyPaths(in: container.managedObjectModel)
        self.workers = (0..<max(1, workers)).map { _ in Worker(context: container.newBackgroundContext(), pretty: pretty) }
    }
    
    /// Stop after the current batch, leaving the destination untouched. Any thread.
    public func cancel() { cancelled.withLock { $0 = true } }
    
    /// Wait for the step in progress to finish. Call after ``cancel()``.
    func waitUntilIdle() { context.performAndWait {} }
    
    /// Pin the exporter's contexts to the store as it is now, before anything else can change it.
    ///
    /// A context pins itself when it first loads data, so this loads one row. The workers take the same snapshot. Call it
    /// from the queue that would make the next change (`privateMOC`), so that change can't come first.
    func pin() {
        let token = context.performAndWait { () -> NSQueryGenerationToken? in
            /// A store in memory (Mac Monitor's at /dev/null, when its file can't be kept) can't: setting the generation
            /// succeeds there, and the next fetch raises an exception Swift can't catch.
            let stores = context.persistentStoreCoordinator?.persistentStores ?? []
            guard !stores.isEmpty,
                  stores.allSatisfy({ $0.type == NSSQLiteStoreType && $0.url?.path != "/dev/null" }) else { return nil }
            do {
                try context.setQueryGenerationFrom(.current)
                let request = NSFetchRequest<NSManagedObjectID>(entityName: "ESMessage")
                request.resultType = .managedObjectIDResultType
                request.fetchLimit = 1
                _ = try context.fetch(request)
            } catch {
                /// Unpinned, the export still works. It just sees changes made while it runs.
            }
            return context.queryGenerationToken
        }
        guard let token else { return }
        for worker in workers { worker.context.performAndWait { try? worker.context.setQueryGenerationFrom(token) } }
    }
    
    private var isCancelled: Bool { cancelled.withLock { $0 } }
    
    /// Choose events and write them to `url`, asynchronously on the exporter's context.
    ///
    /// - Parameters:
    ///   - url: The destination, from the save panel.
    ///   - writeIfEmpty: Write an empty file when no events are chosen (the full trace does, but a selection doesn't).
    ///   - choose: Returns the events in file order. Runs on the exporter's context.
    ///   - progress: Called on the exporter's queue once the events are chosen, at most ten times a second while they're
    ///     written, and once more when the last is.
    ///   - completion: Called on the exporter's queue with the number of events written.
    func run(to url: URL, writeIfEmpty: Bool, choose: @escaping (TelemetryExporter) throws -> [NSManagedObjectID],
             progress: @escaping (Progress) -> Void = { _ in }, completion: @escaping (Result<Int, Error>) -> Void) {
        context.perform {
            let result = Result { () throws -> Int in
                guard !self.isCancelled else { throw CancellationError() }
                let ids = try choose(self)
                /// Choosing every event can't stop partway: a Cancel meanwhile stops here.
                guard !self.isCancelled else { throw CancellationError() }
                guard writeIfEmpty || !ids.isEmpty else { return 0 }
                progress(Progress(written: 0, total: ids.count))
                return try self.write(ids, to: url, progress: progress)
            }
            /// Unpin, so SQLite can checkpoint its log again.
            self.context.reset()
            for worker in self.workers { worker.context.performAndWait { worker.context.reset() } }
            completion(result)
        }
    }
    
    // MARK: Choosing events
    /// Every event saved by `batch`, in file order.
    ///
    /// A trace's events keep the order they were read in (``ESMessage/insert_order``): the trace's file order. A live
    /// recording's are sorted by `mach_time`, ties in the order they reached the store, as a selection is
    /// (``events(withIDs:)``). The Security Extension captures with one Endpoint Security client per event class, whose
    /// events reach the store in the order they were handled: a class that falls behind (a flood of file events) can
    /// arrive hundreds of milliseconds after the others. `mach_time` is the clock every client's messages share.
    ///
    /// - Parameters:
    ///   - batch: The last ``ESMessage/insert_batch`` to include.
    ///   - source: Where the store's events come from.
    /// - Returns: The events' object IDs.
    func allEvents(through batch: Int64, from source: CoreDataController.EventSource) throws -> [NSManagedObjectID] {
        let request = NSFetchRequest<NSManagedObjectID>(entityName: "ESMessage")
        request.resultType = .managedObjectIDResultType
        request.predicate = NSPredicate(format: "insert_batch <= %lld", batch)
        let arrival = NSSortDescriptor(key: "insert_order", ascending: true)
        request.sortDescriptors = source == .live ? [NSSortDescriptor(key: "mach_time", ascending: true), arrival]
            : [arrival]
        return try context.fetch(request)
    }
    
    /// The events with these IDs, found through the indexed `id`, ordered by `mach_time` with ties in `eventIDs` order:
    /// what fetching each one and sorting them by `mach_time` (a stable sort) produced.
    ///
    /// - Parameter eventIDs: The selected events' IDs.
    /// - Returns: The events' object IDs, in file order.
    func events(withIDs eventIDs: [UUID]) throws -> [NSManagedObjectID] {
        let position = Dictionary(eventIDs.enumerated().map { ($1, $0) }, uniquingKeysWith: { first, _ in first })
        let objectID = NSExpressionDescription()
        objectID.name = "objectID"
        objectID.expression = .expressionForEvaluatedObject()
        objectID.expressionResultType = .objectIDAttributeType
        
        var found: [(objectID: NSManagedObjectID, machTime: Int64, position: Int)] = []
        /// One event per ID, like the old fetch with a limit of one.
        var seen = Set<UUID>()
        for start in stride(from: 0, to: eventIDs.count, by: Self.lookupSize) {
            guard !isCancelled else { throw CancellationError() }
            try autoreleasepool {
                let request = NSFetchRequest<NSDictionary>(entityName: "ESMessage")
                request.resultType = .dictionaryResultType
                request.propertiesToFetch = [objectID, "id", "mach_time"]
                request.predicate = NSPredicate(format: "id IN %@", Array(eventIDs[start..<min(start + Self.lookupSize, eventIDs.count)]))
                for row in try context.fetch(request) {
                    guard let oid = row["objectID"] as? NSManagedObjectID, let id = row["id"] as? UUID,
                          let index = position[id], seen.insert(id).inserted else { continue }
                    found.append((oid, (row["mach_time"] as? NSNumber)?.int64Value ?? 0, index))
                }
            }
        }
        found.sort { ($0.machTime, $0.position) < ($1.machTime, $1.position) }
        return found.map(\.objectID)
    }
    
    // MARK: Writing
    /// Encode `ids` into a temporary file, a round of batches at a time (one per worker, in parallel), then move it over
    /// `url`.
    ///
    /// - Parameters:
    ///   - ids: The events, in file order.
    ///   - url: The destination.
    ///   - progress: Receives how many have been written, at most ten times a second and once at the end.
    /// - Returns: The number of events written.
    private func write(_ ids: [NSManagedObjectID], to url: URL, progress: (Progress) -> Void) throws -> Int {
        let (handle, temporary) = try Self.temporaryFile(beside: url)
        var finished = false
        defer { if !finished { unlink(temporary.path) } }
        var buffer = Data(), written = 0, reported = DispatchTime.now().uptimeNanoseconds
        let batches = stride(from: 0, to: ids.count, by: Self.batchSize).map {
            Array(ids[$0..<min($0 + Self.batchSize, ids.count)])
        }
        do {
            for round in stride(from: 0, to: batches.count, by: workers.count) {
                guard !isCancelled else { throw CancellationError() }
                let jobs = Array(batches[round..<min(round + workers.count, batches.count)])
                DispatchQueue.concurrentPerform(iterations: jobs.count) { index in
                    workers[index].encode(jobs[index], prefetch: prefetch)
                }
                for worker in workers.prefix(jobs.count) {
                    let records = try worker.records()
                    guard records.count > 0 else { continue }
                    if written > 0 { buffer.append(0x0A) }
                    buffer.append(records.json)
                    written += records.count
                }
                if buffer.count >= 1 << 20 {
                    try handle.write(contentsOf: buffer)
                    buffer.removeAll(keepingCapacity: true)
                }
                let now = DispatchTime.now().uptimeNanoseconds
                if now - reported >= reportInterval {
                    reported = now
                    progress(Progress(written: written, total: ids.count))
                }
            }
            /// A Cancel during the last round, which the loop no longer checks for.
            guard !isCancelled else { throw CancellationError() }
            try handle.write(contentsOf: buffer)
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }
        /// Or during the last write: only the rename itself can't be stopped.
        guard !isCancelled else { throw CancellationError() }
        try Self.replace(url, with: temporary)
        finished = true
        progress(Progress(written: written, total: ids.count))
        return written
    }
    
    /// Create a hidden temporary file next to `url`, as `String.write(to:atomically:encoding:)` does, so the export
    /// takes the folder's group and inherited permissions and the final rename stays on one volume.
    ///
    /// - Parameter url: The destination.
    /// - Returns: The open file and its path.
    private static func temporaryFile(beside url: URL) throws -> (FileHandle, URL) {
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        /// Created like any new file (0666 less the umask), so a new export gets the same permissions as before.
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL, 0o666)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        return (FileHandle(fileDescriptor: descriptor, closeOnDealloc: true), temporary)
    }
    
    /// Keep the replaced file's permissions and rename over it.
    ///
    /// - Parameters:
    ///   - url: The destination.
    ///   - temporary: The finished file.
    private static func replace(_ url: URL, with temporary: URL) throws {
        if let mode = try? FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] {
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: temporary.path)
        }
        guard rename(temporary.path, url.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
}


// MARK: - Workers
extension TelemetryExporter {
    /// Fetches and encodes one batch at a time on its own context, pinned to the export's snapshot. Used by one thread
    /// at a time: the exporter hands it a batch, then reads its records once every worker has finished.
    final class Worker {
        let context: NSManagedObjectContext
        private let pretty: Bool
        /// Writes JSONL records where it sorts keys as `JSONEncoder` does (``ProcessHelpers/eventToJSON(value:)``
        /// otherwise).
        private let encoder: StreamingJSONEncoder?
        /// The last batch's records joined by newlines, and how many there are, or why there are none.
        private var result: Result<(json: Data, count: Int), Error> = .success((Data(), 0))
        
        /// - Parameters:
        ///   - context: Its own context.
        ///   - pretty: Pretty-printed JSON (`true`) or JSONL (`false`).
        init(context: NSManagedObjectContext, pretty: Bool) {
            self.context = context
            self.pretty = pretty
            encoder = !pretty && StreamingJSONEncoder.sortsKeysAsJSONEncoderDoes
                ? StreamingJSONEncoder(sortsKeys: true, escapesSlashes: false) : nil
        }
        
        /// Fetch a batch, fully loaded with every relationship its events encode, and encode its events in `batch`
        /// order: the events still in the store, each as `eventToJSON` writes it (`{}` for one it can't encode).
        ///
        /// - Parameters:
        ///   - batch: The events' object IDs.
        ///   - prefetch: Every to-one relationship an event encodes.
        func encode(_ batch: [NSManagedObjectID], prefetch: [String]) {
            context.performAndWait {
                result = Result {
                    try autoreleasepool {
                        let request = NSFetchRequest<ESMessage>(entityName: "ESMessage")
                        request.predicate = NSPredicate(format: "self IN %@", batch)
                        request.returnsObjectsAsFaults = false
                        request.relationshipKeyPathsForPrefetching = prefetch
                        let loaded = Dictionary(try context.fetch(request).map { ($0.objectID, $0) },
                                                uniquingKeysWith: { first, _ in first })
                        var json = Data(), count = 0
                        for message in batch.compactMap({ loaded[$0] }) {
                            if count > 0 { json.append(0x0A) }
                            if let encoder {
                                json.append((try? encoder.encode(message)) ?? Data("{}".utf8))
                            } else {
                                let text = pretty ? ProcessHelpers.eventToPrettyJSON(value: message)
                                    : ProcessHelpers.eventToJSON(value: message)
                                json.append(contentsOf: text.utf8)
                            }
                            count += 1
                        }
                        /// Not reset(): that would also unpin the context from the snapshot.
                        context.refreshAllObjects()
                        return (json, count)
                    }
                }
            }
        }
        
        /// The last batch's records.
        ///
        /// - Returns: Their JSON joined by newlines, and how many there are.
        /// - Throws: The error fetching them.
        func records() throws -> (json: Data, count: Int) { try result.get() }
    }
}


// MARK: - Records
public extension ESMessage {
    /// Every to-one relationship an event's record encodes, for `relationshipKeyPathsForPrefetching`: derived from the
    /// model, so new event types are prefetched too.
    ///
    /// Six deep reaches the deepest path an event encodes, `event.rename.destination.new_path.dir.stat` (and `create`'s).
    ///
    /// - Parameter model: The event store's model.
    /// - Returns: The key paths, or none if the model has no `ESMessage`.
    static func recordPrefetchKeyPaths(in model: NSManagedObjectModel) -> [String] {
        /// - Parameters:
        ///   - entity: The entity to start from.
        ///   - prefix: The path to `entity`.
        ///   - depth: How many relationships deep to go.
        func paths(from entity: NSEntityDescription, prefix: String = "", depth: Int = 6) -> [String] {
            guard depth > 0 else { return [] }
            return entity.relationshipsByName.sorted { $0.key < $1.key }.flatMap { name, relationship -> [String] in
                guard !relationship.isToMany, let destination = relationship.destinationEntity else { return [] }
                let path = prefix.isEmpty ? name : "\(prefix).\(name)"
                return [path] + paths(from: destination, prefix: path, depth: depth - 1)
            }
        }
        return model.entitiesByName["ESMessage"].map { paths(from: $0) } ?? []
    }
}
