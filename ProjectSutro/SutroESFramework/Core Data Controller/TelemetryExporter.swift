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
/// ``ProcessHelpers/eventToPrettyJSON(value:)``, joined by "\n" with no trailing newline, saved the way
/// `String.write(to:atomically:encoding:)` saves.
///
/// The context is pinned to the store as it was when the export started (``pin()``), so events cleared meanwhile still
/// export. While pinned, SQLite can't fold its write-ahead log back into the store, so the log grows with whatever changes
/// during the export (measured: about 4 KB per event cleared, plus each inserted event's size) until the export finishes.
final class TelemetryExporter {
    /// Events fetched and encoded at a time.
    static let batchSize = 500
    /// Selected event IDs looked up per fetch.
    static let lookupSize = 10_000
    
    private let context: NSManagedObjectContext
    private let pretty: Bool
    /// Every to-one relationship an event encodes, fetched along with each batch.
    private let prefetch: [String]
    private let cancelled = OSAllocatedUnfairLock(initialState: false)
    
    /// - Parameters:
    ///   - container: The event store.
    ///   - pretty: Pretty-printed JSON (`true`) or JSONL (`false`).
    init(container: NSPersistentContainer, pretty: Bool) {
        context = container.newBackgroundContext()
        self.pretty = pretty
        prefetch = container.managedObjectModel.entitiesByName["ESMessage"].map { Self.prefetchKeyPaths(from: $0) } ?? []
    }
    
    /// Stop after the current batch, leaving the destination untouched.
    func cancel() { cancelled.withLock { $0 = true } }
    
    /// Wait for the step in progress to finish. Call after ``cancel()``.
    func waitUntilIdle() { context.performAndWait {} }
    
    /// Pin the exporter's context to the store as it is now, before anything else can change it.
    ///
    /// A context pins itself when it first loads data, so this loads one row. Call it from the queue that would make the
    /// next change (`privateMOC`), so that change can't come first.
    func pin() {
        context.performAndWait {
            do {
                try context.setQueryGenerationFrom(.current)
                let request = NSFetchRequest<NSManagedObjectID>(entityName: "ESMessage")
                request.resultType = .managedObjectIDResultType
                request.fetchLimit = 1
                _ = try context.fetch(request)
            } catch {
                /// Unpinned, the export still works; it just sees changes made while it runs.
            }
        }
    }
    
    private var isCancelled: Bool { cancelled.withLock { $0 } }
    
    /// Choose events and write them to `url`, asynchronously on the exporter's context.
    ///
    /// - Parameters:
    ///   - url: The destination, from the save panel.
    ///   - writeIfEmpty: Write an empty file when no events are chosen (the full trace does; a selection doesn't).
    ///   - choose: Returns the events in file order. Runs on the exporter's context.
    ///   - completion: Called on the exporter's queue with the number of events written.
    func run(to url: URL, writeIfEmpty: Bool, choose: @escaping (TelemetryExporter) throws -> [NSManagedObjectID],
             completion: @escaping (Result<Int, Error>) -> Void) {
        context.perform {
            let result = Result { () throws -> Int in
                guard !self.isCancelled else { throw CancellationError() }
                let ids = try choose(self)
                guard writeIfEmpty || !ids.isEmpty else { return 0 }
                return try self.write(ids, to: url)
            }
            /// Unpin, so SQLite can checkpoint its log again.
            self.context.reset()
            completion(result)
        }
    }
    
    // MARK: Choosing events
    /// Every event saved by `batch`, in the order they reached the store (``ESMessage/insert_order``): the order they
    /// were recorded in, or a trace's file order.
    ///
    /// - Parameter batch: The last ``ESMessage/insert_batch`` to include.
    /// - Returns: The events' object IDs.
    func allEvents(through batch: Int64) throws -> [NSManagedObjectID] {
        let request = NSFetchRequest<NSManagedObjectID>(entityName: "ESMessage")
        request.resultType = .managedObjectIDResultType
        request.predicate = NSPredicate(format: "insert_batch <= %lld", batch)
        request.sortDescriptors = [NSSortDescriptor(key: "insert_order", ascending: true)]
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
    /// Encode `ids` a batch at a time into a temporary file, then move it over `url`.
    ///
    /// - Parameters:
    ///   - ids: The events, in file order.
    ///   - url: The destination.
    /// - Returns: The number of events written.
    private func write(_ ids: [NSManagedObjectID], to url: URL) throws -> Int {
        let (handle, temporary) = try Self.temporaryFile(beside: url)
        var finished = false
        defer { if !finished { unlink(temporary.path) } }
        var buffer = Data(), written = 0
        do {
            for start in stride(from: 0, to: ids.count, by: Self.batchSize) {
                guard !isCancelled else { throw CancellationError() }
                try autoreleasepool {
                    for message in try fetch(Array(ids[start..<min(start + Self.batchSize, ids.count)])) {
                        if written > 0 { buffer.append(0x0A) }
                        let json = pretty ? ProcessHelpers.eventToPrettyJSON(value: message) : ProcessHelpers.eventToJSON(value: message)
                        buffer.append(contentsOf: json.utf8)
                        written += 1
                    }
                    if buffer.count >= 1 << 20 {
                        try handle.write(contentsOf: buffer)
                        buffer.removeAll(keepingCapacity: true)
                    }
                    /// Not reset(): that would also unpin the context from the snapshot.
                    context.refreshAllObjects()
                }
            }
            try handle.write(contentsOf: buffer)
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }
        try Self.replace(url, with: temporary)
        finished = true
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
    
    /// One batch of events, fully loaded with every relationship they encode, in `batch` order.
    ///
    /// - Parameter batch: The events' object IDs.
    /// - Returns: The events still in the store.
    private func fetch(_ batch: [NSManagedObjectID]) throws -> [ESMessage] {
        let request = NSFetchRequest<ESMessage>(entityName: "ESMessage")
        request.predicate = NSPredicate(format: "self IN %@", batch)
        request.returnsObjectsAsFaults = false
        request.relationshipKeyPathsForPrefetching = prefetch
        let loaded = Dictionary(try context.fetch(request).map { ($0.objectID, $0) }, uniquingKeysWith: { first, _ in first })
        return batch.compactMap { loaded[$0] }
    }
    
    /// Finish the way `String.write(to:atomically:true,encoding:.utf8)` does: tag the text encoding, keep the replaced
    /// file's permissions, and rename over it.
    ///
    /// - Parameters:
    ///   - url: The destination.
    ///   - temporary: The finished file.
    private static func replace(_ url: URL, with temporary: URL) throws {
        _ = "utf-8;134217984".withCString { setxattr(temporary.path, "com.apple.TextEncoding", $0, strlen($0), 0, 0) }
        if let mode = try? FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] {
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: temporary.path)
        }
        guard rename(temporary.path, url.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
    
    /// Every to-one relationship path from `entity`, up to `depth` deep, derived from the model so new event types are
    /// prefetched too.
    ///
    /// Six deep reaches the deepest path an event encodes, `event.rename.destination.new_path.dir.stat` (and `create`'s).
    ///
    /// - Parameters:
    ///   - entity: The entity to start from.
    ///   - prefix: The path to `entity`.
    ///   - depth: How many relationships deep to go.
    /// - Returns: Key paths for `relationshipKeyPathsForPrefetching`.
    private static func prefetchKeyPaths(from entity: NSEntityDescription, prefix: String = "", depth: Int = 6) -> [String] {
        guard depth > 0 else { return [] }
        return entity.relationshipsByName.sorted { $0.key < $1.key }.flatMap { name, relationship -> [String] in
            guard !relationship.isToMany, let destination = relationship.destinationEntity else { return [] }
            let path = prefix.isEmpty ? name : "\(prefix).\(name)"
            return [path] + prefetchKeyPaths(from: destination, prefix: path, depth: depth - 1)
        }
    }
}
