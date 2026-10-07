//
//  CoreDataController.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/7/23.
//

import Foundation
import CoreData
import OSLog
import os
import AppKit
import UniformTypeIdentifiers

/// Exposes functions and helpers to manage system event entities stored in Core Data
///
/// Reference: [Setting up a Core Data Stack](https://developer.apple.com/documentation/coredata/setting_up_a_core_data_stack)
///
public class CoreDataController {
    public static let shared = CoreDataController()
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "CoreDataController")
    
    /// Main context
    ///
    /// On the main thread: `container.viewContext`. This main context is designed to be used
    /// to update the UI.
    public var container: NSPersistentContainer
    
    /// Background context
    ///
    /// Designed for asyncronous operations like batch inserting.
    let privateMOC: NSManagedObjectContext
    
    /// The rows `privateMOC`'s events share: one `ESProcess` (with its tokens and files) per process rather than one per
    /// event, and one `ESFile` per file and stat (#84). Kept in `privateMOC.userInfo`; only touched on its queue.
    private let rowCaches = EventRowCaches()
    


    /// Where the event store lives: a SQLite file in Mac Monitor's caches folder, or `nil` if it couldn't be set up there
    /// and events are kept in memory instead.
    ///
    /// Events used to live in an in-memory store (`/dev/null`), so a long trace could exhaust memory (#84). On disk, only
    /// SQLite's page cache and the objects being shown stay in memory, and the trace is bounded by disk space, like
    /// Process Monitor's backing file. It's still one trace per launch, and each running copy of Mac Monitor has its own:
    /// the file is deleted at quit (or, after a crash, at the next launch).
    public var storeURL: URL? { storeFile?.url }
    private let storeFile: EventStoreFile?
    
    /// Can events be saved? Not without a store (a save or batch delete would raise an exception Swift can't catch), and
    /// not once Mac Monitor is quitting and the store's files are gone (Core Data would make a new, empty store).
    let canSave: OSAllocatedUnfairLock<Bool>
    
    /// Set up the on-disk Core Data PSC named: `SystemEvents`, starting from an empty store.
    init() {
        container = NSPersistentContainer(name: "SystemEvents")
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent(Bundle.main.bundleIdentifier ?? "com.swiftlydetecting.SutroESFramework", isDirectory: true)
        storeFile = EventStoreFile(in: caches)
        
        let description = container.persistentStoreDescriptions[0]
        /// The store is thrown away at every launch, so fsync-level durability buys nothing and would slow every insert.
        description.setOption(["synchronous": "OFF"] as NSDictionary, forKey: NSSQLitePragmasOption)
        if let storeURL = storeFile?.url {
            description.url = storeURL
            Self.loadStores(of: container)
        }
        /// A store in memory, as before #84, beats no store at all.
        if container.persistentStoreCoordinator.persistentStores.isEmpty {
            CoreDataController.logger.fault("Unable to keep events on disk; keeping them in memory instead")
            description.url = URL(fileURLWithPath: "/dev/null")
            Self.loadStores(of: container)
        }
        canSave = OSAllocatedUnfairLock(initialState: !container.persistentStoreCoordinator.persistentStores.isEmpty)
        
        container.viewContext.automaticallyMergesChangesFromParent = true
        
        // New background context to handle off-main thread tasks
        privateMOC = container.newBackgroundContext()
        privateMOC.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy
        /// Don't keep every inserted object alive: `insertSystemEvents` resets the context after each save.
        privateMOC.retainsRegisteredObjects = false
        privateMOC.performAndWait { privateMOC.userInfo[EventRowCaches.userInfoKey] = rowCaches }
        
        /// Give the disk space back when Mac Monitor quits, after stopping any export still reading the store. (A crash
        /// leaves the files for the next launch to delete.)
        NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: nil) { [storeFile, exports, canSave] _ in
            let running = exports.withLock { Array($0.values) }
            running.forEach { $0.cancel() }
            running.forEach { $0.waitUntilIdle() }
            canSave.withLock { $0 = false }
            storeFile?.delete()
        }
    }
    
    /// Load `container`'s store, logging a failure.
    ///
    /// - Parameter container: The container to load.
    private static func loadStores(of container: NSPersistentContainer) {
        container.loadPersistentStores { _, error in
            if let error = error as NSError? {
                CoreDataController.logger.error("Unable to create the Core Data PSC \(error)!")
            }
        }
    }
    
    // MARK: - Mutators
    
    /// Posted (on the private context's queue) after each batch of events is saved. `userInfo[insertedObjectIDsKey]` holds
    /// the permanent `NSManagedObjectID`s of the new `ESMessage`s, in insert order, and `userInfo[insertBatchKey]` the
    /// `Int64` stamped on them as ``ESMessage/insert_batch``. Batches count up from 1 and are posted in order.
    public static let eventsInserted = Notification.Name("com.swiftlydetecting.agent.eventsInserted")
    public static let insertedObjectIDsKey = "insertedObjectIDs"
    public static let insertBatchKey = "insertBatch"
    
    /// Posted on the calling thread (the main thread) by ``clearSystemEvents(source:)`` before anything is deleted. Views
    /// must let go of every event (and anything reached through one) right away: the delete starts on the next turn of the
    /// run loop.
    public static let eventsWillClear = Notification.Name("com.swiftlydetecting.agent.eventsWillClear")
    
    /// Posted on the main thread once ``clearSystemEvents(source:)`` has deleted everything, so views can load events
    /// again.
    public static let eventsDidClear = Notification.Name("com.swiftlydetecting.agent.eventsDidClear")
    
    /// Is a Clear deleting events right now (between ``eventsWillClear`` and ``eventsDidClear``)? Main thread only.
    public var isClearing: Bool { clearsInProgress > 0 }
    private var clearsInProgress = 0
    
    /// The last ``ESMessage/insert_batch`` saved (0 before the first save). Readable from any thread, so a reader that
    /// starts following ``eventsInserted`` mid-trace knows which batches it missed.
    public var lastInsertBatch: Int64 { savedBatch.withLock { $0 } }
    private let savedBatch = OSAllocatedUnfairLock(initialState: Int64(0))
    
    /// Events inserted but not yet saved. Normally just the current batch; after a failed save the earlier events stay
    /// here and are saved (and announced) with the next batch. Only touched on `privateMOC`'s queue.
    private var unsavedEvents: [ESMessage] = []
    
    /// The most events kept for another try after failed saves. Past this, saves are failing for good (the disk is full)
    /// and the events are dropped, rather than kept in memory until Mac Monitor runs out of it (#84).
    private static let maxUnsavedEvents = 20_000
    
    /// Recorded events that happened before this are discarded on insert. Set by ``clearSystemEvents(source:)`` so events
    /// recorded before a Clear, but still on their way from the Security Extension, can't refill the table. While a trace
    /// is open it's `.distantFuture`, so no recorded event mixes into the trace. Only touched on `privateMOC`'s queue.
    ///
    /// Wall-clock time, not `mach_time`: under Rosetta this process's `mach_absolute_time()` uses a different timebase
    /// than the (native) Security Extension's, so the two can't be compared.
    private var discardBefore: Date = .distantPast
    
    /// Where the events in the store come from.
    public enum EventSource: Equatable {
        /// Recorded by the Security Extension.
        case live
        /// Read from a trace file (File > Open Trace…).
        case trace(URL)
    }
    
    /// Where the events in the store come from. Set by ``clearSystemEvents(source:)``. Main thread only.
    public private(set) var source: EventSource = .live
    
    /// Clears requested so far. Main thread only.
    private var clearsRequested = 0
    /// The last Clear to reach `privateMOC`. A trace's inserts carry the Clear that opened it, so a trace that has since
    /// been closed or replaced can't add to the store. Only touched on `privateMOC`'s queue.
    private var currentClear = 0
    
    /// The ``ESMessage/insert_order`` of the next event inserted. Only touched on `privateMOC`'s queue.
    private var nextInsertOrder: Int64 = 0
    
    /// The trace being read, stopped by the next Clear. Main thread only.
    private weak var currentImport: TraceImporter?
    
    /// Inserts a batch of system events into the private context in a single background transaction.
    ///
    /// Each event records the audit token of the process that instigated it and, for `EXEC` and `FORK`, the token of the
    /// process it created. ``ESMessage/correlated_array`` uses those (indexed) to find a process's events when they're
    /// viewed, so inserting never has to look up or modify a parent (#84).
    ///
    /// Events of the same process share one `ESProcess` row (with its audit tokens, executable, tty, and stats), and
    /// equal files share one `ESFile` (see ``EventRowCaches``): about 3 events per process, each of which used to store
    /// its own copy. Each event keeps the process `id` it exports.
    ///
    /// After a successful save the context is reset so it doesn't accumulate every event ever inserted. On failure the
    /// objects are kept and retried with the next batch's save rather than lost (up to 20,000 events).
    ///
    /// Recorded events that happened before the last Clear are discarded, and while a trace is open every recorded event
    /// is (see ``clearSystemEvents(source:)``).
    ///
    ///  - Parameters:
    ///    - messages: An array of system events (`Message`) to insert.
    ///    - completion: Called on the private context's queue once the batch has been saved (or failed to save).
    ///      ``EndpointSecurityManager`` uses it to acknowledge XPC batches, which is what gives the Security Extension
    ///      back-pressure when inserts fall behind.
    ///
    public func insertSystemEvents(messages: [Message], completion: @escaping () -> Void = {}) {
        insert(messages, keeping: { $0.message_darwin_time >= self.discardBefore }) { _ in completion() }
    }
    
    /// Inserts a batch of events read from a trace file (see ``TraceImporter``), however long ago they happened.
    ///
    /// A batch that fails to save is dropped rather than retried with the next save: the trace can be read again, and the
    /// store then holds exactly the events reported saved.
    ///
    /// - Parameters:
    ///   - messages: The events, in file order.
    ///   - clear: The Clear that opened the trace (``clearSystemEvents(source:)``). Once another Clear has run the trace is
    ///     gone, and the batch is dropped.
    ///   - completion: Called on the private context's queue with whether the batch was saved.
    func insertTraceEvents(_ messages: [Message], clear: Int, completion: @escaping (Bool) -> Void) {
        insert(messages, keeping: { _ in clear == self.currentClear }) { saved in
            if !saved { self.discardUnsavedEvents() }
            completion(saved)
        }
    }
    
    /// Insert the events `keep` accepts in a single background transaction, save, and announce them (``eventsInserted``).
    ///
    /// - Parameters:
    ///   - messages: The events.
    ///   - keep: Decides, on the private context's queue, which events to store.
    ///   - completion: Called on the private context's queue with whether the batch was saved (`true` when nothing needed
    ///     saving).
    private func insert(_ messages: [Message], keeping keep: @escaping (Message) -> Bool,
                        completion: @escaping (Bool) -> Void) {
        guard !messages.isEmpty else { return completion(true) }
        
        privateMOC.perform {
            let context = self.privateMOC
            var saved = false
            defer { completion(saved) }
            
            guard self.canSave.withLock({ $0 }) else { return }
            let batch = self.lastInsertBatch + 1
            for message in messages where keep(message) {
                let systemESMessage = ESMessage(from: message, insertIntoManagedObjectContext: context)
                systemESMessage.insert_order = self.nextInsertOrder
                self.nextInsertOrder += 1
                systemESMessage.instigator_audit_token = message.process.audit_token_string
                systemESMessage.denormalize(from: message)
                self.unsavedEvents.append(systemESMessage)
            }
            
            guard context.hasChanges else { saved = true; return }
            self.unsavedEvents.forEach { $0.insert_batch = batch }
            do {
                try context.save()
                saved = true
                let insertedIDs = self.unsavedEvents.map(\.objectID)
                self.savedBatch.withLock { $0 = batch }
                self.unsavedEvents = []
                /// Before the reset: the shared rows are kept by their (now permanent) IDs.
                self.rowCaches.didSave()
                context.reset()
                NotificationCenter.default.post(name: Self.eventsInserted, object: self, userInfo: [Self.insertedObjectIDsKey: insertedIDs, Self.insertBatchKey: batch])
            } catch {
                /// The unsaved rows are still retried with the next save (or dropped with their events below), but they're
                /// no longer handed out: a failed save may leave them with IDs that aren't stored.
                self.rowCaches.forget()
                CoreDataController.logger.error("Error saving context after batch insert: \(error.localizedDescription)")
                guard self.unsavedEvents.count > Self.maxUnsavedEvents else { return }
                CoreDataController.logger.fault("Dropped \(self.unsavedEvents.count) events that could not be saved")
                self.discardUnsavedEvents()
            }
        }
    }
    
    /// Drop every event inserted but not saved, and the shared rows made for them. On `privateMOC`'s queue only.
    private func discardUnsavedEvents() {
        privateMOC.rollback()
        unsavedEvents = []
        rowCaches.forget()
    }
    
    ///  Remove all events from the event store
    ///
    ///  Removes every entity in the `SystemEvents` store: the `ESMessage`s and the process, file, and event records they
    ///  point to (deleting only the `ESMessage`s left about three quarters of the store behind until quit). To do this we:
    ///  1) Post ``eventsWillClear`` so the event tables (and Event Facts windows) let go of their events
    ///  2) On the next turn of the run loop, create a batch delete request per entity and execute them on the private context
    ///  3) Merge the deletions into the `container.viewContext` connected to the UI, and post ``eventsDidClear``
    ///
    ///  The delete runs in the background (about two minutes at a million events) behind inserts already queued; inserts
    ///  that come after it wait for it. Events that happened before this call are discarded even if they arrive later.
    ///
    ///  A Clear also closes any trace: a trace still being read stops, and its batches still on their way are dropped.
    ///
    ///  Call on the main thread.
    ///
    /// - Parameter source: What the store holds after the Clear: ``EventSource/live`` (the toolbar's Clear and Start), or a
    ///   trace about to be read (``openTrace(at:progress:completion:)``), which keeps out every recorded event until the
    ///   next Clear.
    /// - Returns: The Clear's number, which a trace's inserts carry.
    @discardableResult
    public func clearSystemEvents(source: EventSource = .live) -> Int {
        let clearedAt = Date()
        clearsInProgress += 1
        clearsRequested += 1
        let clear = clearsRequested
        self.source = source
        currentImport?.stop()
        NotificationCenter.default.post(name: Self.eventsWillClear, object: self)
        
        /// Everything is deleted, but only what the view context has loaded needs to hear about it. Asking the deletes for
        /// every deleted ID would build (and merge) one per row.
        let viewContext = container.viewContext
        let loaded = viewContext.registeredObjects.map(\.objectID)
        
        /// Queued now, so inserts that come after the Clear also come after the delete.
        let turn = DispatchSemaphore(value: 0)
        RunLoop.main.perform { turn.signal() }
        privateMOC.perform {
            /// One turn of the main run loop lets SwiftUI apply what views did on ``eventsWillClear`` before rows start
            /// disappearing.
            turn.wait()
            /// Anything recorded up to the Clear goes, including events still on their way from the Security Extension and
            /// any left unsaved by a failed save. A trace keeps out every recorded event until it's closed.
            self.discardBefore = source == .live ? clearedAt : .distantFuture
            self.currentClear = clear
            /// The shared rows are deleted (or, unsaved, rolled back) with everything else.
            self.discardUnsavedEvents()
            var replaced = false
            do {
                for entity in self.container.managedObjectModel.entities where entity.superentity == nil {
                    guard self.canSave.withLock({ $0 }) else { break }
                    guard let name = entity.name else { continue }
                    let deleteRequest = NSBatchDeleteRequest(fetchRequest: NSFetchRequest(entityName: name))
                    deleteRequest.resultType = .resultTypeStatusOnly
                    try self.privateMOC.execute(deleteRequest)
                    /// A delete the disk has no room for reports success: count what's left.
                    guard try self.privateMOC.count(for: NSFetchRequest(entityName: name)) == 0 else {
                        throw CocoaError(.fileWriteOutOfSpace)
                    }
                }
                /// Nothing is registered here after the rollback, so there are no deletions to merge.
                self.privateMOC.reset()
            } catch {
                CoreDataController.logger.error("Error clearing system events: \(error.localizedDescription)")
                replaced = self.replaceStore()
            }
            
            DispatchQueue.main.async {
                /// The view context is not aware of the changes yet, so we merge them, or, if the store was taken away,
                /// forget everything it loaded from it.
                if replaced { viewContext.reset() }
                else { NSManagedObjectContext.mergeChanges(fromRemoteContextSave: [NSDeletedObjectsKey: loaded], into: [viewContext]) }
                self.clearsInProgress -= 1
                NotificationCenter.default.post(name: Self.eventsDidClear, object: self)
            }
        }
        return clear
    }
    
    /// Replace the store with an empty one, for a Clear whose deletes failed: SQLite logs a delete before making it, which
    /// a full disk (most easily filled by a trace) has no room for, while emptying the store's files frees space. Not
    /// while an export reads the store. On `privateMOC`'s queue only, after it has let go of every object.
    ///
    /// - Returns: Whether the store was taken away, so every context must forget the objects it loaded from it.
    private func replaceStore() -> Bool {
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
            }
            /// The emptied store, or (as when one can't be made at launch) one in memory.
            for location in [url, URL(fileURLWithPath: "/dev/null")] {
                if (try? coordinator.addPersistentStore(type: .sqlite, at: location, options: options)) != nil { return }
            }
            canSave.withLock { $0 = false }
            CoreDataController.logger.fault("Unable to reopen the event store; no more events can be kept")
        }
        return removed
    }
    
    // MARK: - Open Trace
    
    /// Replace the store's events with a trace file's, read in the background (see ``TraceImporter``), like opening a
    /// saved Process Monitor log (#38).
    ///
    /// Clears the store first (``eventsWillClear`` and ``eventsDidClear``); then the trace's events arrive the way a
    /// recording's do (``eventsInserted``), so the tables fill in as the file is read. Recorded events are dropped until
    /// the next ``clearSystemEvents(source:)`` closes the trace. Call on the main thread, once
    /// ``TraceImporter/preflight(_:)`` has accepted the file.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - progress: Called on the main thread, at most ten times a second.
    ///   - completion: Called on the main thread once, when the file has been read, or reading stopped or failed.
    /// - Returns: The import, to stop it.
    @discardableResult
    public func openTrace(at url: URL, progress: @escaping (TraceImporter.Progress) -> Void = { _ in },
                          completion: @escaping (TraceImporter.Summary) -> Void) -> TraceImporter {
        let importer = TraceImporter(url: url, store: self, clear: clearSystemEvents(source: .trace(url)))
        currentImport = importer
        importer.run(progress: progress, completion: completion)
        return importer
    }
    
    /// The number of events in the store, counted by SQLite. Main thread only.
    public var eventCount: Int {
        (try? container.viewContext.count(for: ESMessage.fetchRequest())) ?? 0
    }
    
    
    
    /// Exports in progress, so quitting can stop them before the store is deleted.
    let exports = OSAllocatedUnfairLock(initialState: [ObjectIdentifier: TelemetryExporter]())
}
