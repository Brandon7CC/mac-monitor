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
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "CoreDataController")
    
    /// Main context
    ///
    /// On the main thread: `container.viewContext`. This main context is designed to be used
    /// to update the UI.
    public var container: NSPersistentContainer
    
    /// Background context
    ///
    /// Designed for asyncronous operations like batch inserting.
    private let privateMOC: NSManagedObjectContext
    
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
    private let canSave: OSAllocatedUnfairLock<Bool>
    
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
    
    /// Posted on the calling thread (the main thread) by ``clearSystemEvents()`` before anything is deleted. Views must let
    /// go of every event (and anything reached through one) right away: the delete starts on the next turn of the run loop.
    public static let eventsWillClear = Notification.Name("com.swiftlydetecting.agent.eventsWillClear")
    
    /// Posted on the main thread once ``clearSystemEvents()`` has deleted everything, so views can load events again.
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
    
    /// Events that happened before this are discarded on insert. Set by ``clearSystemEvents()`` so events recorded before a
    /// Clear, but still on their way from the Security Extension, can't refill the table. Only touched on `privateMOC`'s
    /// queue.
    ///
    /// Wall-clock time, not `mach_time`: under Rosetta this process's `mach_absolute_time()` uses a different timebase
    /// than the (native) Security Extension's, so the two can't be compared.
    private var discardBefore: Date = .distantPast
    
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
    ///  - Parameters:
    ///    - messages: An array of system events (`Message`) to insert.
    ///    - completion: Called on the private context's queue once the batch has been saved (or failed to save).
    ///      ``EndpointSecurityManager`` uses it to acknowledge XPC batches, which is what gives the Security Extension
    ///      back-pressure when inserts fall behind.
    ///
    public func insertSystemEvents(messages: [Message], completion: @escaping () -> Void = {}) {
        guard !messages.isEmpty else { return completion() }
        
        privateMOC.perform {
            let context = self.privateMOC
            defer { completion() }
            
            guard self.canSave.withLock({ $0 }) else { return }
            let batch = self.lastInsertBatch + 1
            for message in messages where message.message_darwin_time >= self.discardBefore {
                let systemESMessage = ESMessage(from: message, insertIntoManagedObjectContext: context)
                systemESMessage.instigator_audit_token = message.process.audit_token_string
                systemESMessage.denormalize(from: message)
                self.unsavedEvents.append(systemESMessage)
            }
            
            guard context.hasChanges else { return }
            self.unsavedEvents.forEach { $0.insert_batch = batch }
            do {
                try context.save()
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
                context.rollback()
                self.unsavedEvents = []
            }
        }
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
    ///  Call on the main thread.
    ///
    public func clearSystemEvents() {
        let clearedAt = Date()
        clearsInProgress += 1
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
            /// any left unsaved by a failed save.
            self.discardBefore = clearedAt
            self.privateMOC.rollback()
            self.unsavedEvents = []
            /// The shared rows are deleted (or, unsaved, rolled back) with everything else.
            self.rowCaches.forget()
            do {
                for entity in self.container.managedObjectModel.entities where entity.superentity == nil {
                    guard self.canSave.withLock({ $0 }) else { break }
                    guard let name = entity.name else { continue }
                    let deleteRequest = NSBatchDeleteRequest(fetchRequest: NSFetchRequest(entityName: name))
                    deleteRequest.resultType = .resultTypeStatusOnly
                    try self.privateMOC.execute(deleteRequest)
                }
                /// Nothing is registered here after the rollback, so there are no deletions to merge.
                self.privateMOC.reset()
            } catch {
                CoreDataController.logger.error("Error clearing system events: \(error.localizedDescription)")
            }
            
            DispatchQueue.main.async {
                // The view context is not aware of the changes yet, so we merge them.
                NSManagedObjectContext.mergeChanges(fromRemoteContextSave: [NSDeletedObjectsKey: loaded], into: [viewContext])
                self.clearsInProgress -= 1
                NotificationCenter.default.post(name: Self.eventsDidClear, object: self)
            }
        }
    }
    
    // MARK: - Accessors
    
    ///  Given an entitiy `id` attempt to return its `ESMessage` representation from the store (through the indexed `id`).
    ///
    ///  - Parameters:
    ///     - id: The `UUID` of the entity to fetch from the Core Data store.
    /// - Returns: The object representation of the entity: `ESMessage?`
    ///
    public func getEntityByID(id: UUID) -> ESMessage? {
        let request = NSFetchRequest<ESMessage>(entityName: "ESMessage")
        request.predicate = NSPredicate(format: "id == %@", id as CVarArg)
        request.returnsObjectsAsFaults = false
        request.fetchLimit = 1
        
        do {
            // Fetches on the viewContext, so this must be called from the main thread.
            let result = try self.container.viewContext.fetch(request)
            return result.first
        } catch {
            CoreDataController.logger.error("Could not find the Core Data record by UUID of: \(id)")
        }
        
        return nil
    }
    
    /// Get all `EXEC` events in a given process group.
    ///
    /// - Parameters:
    ///   - message: Provide a system event and we'll extract the `group_id` field to find the others in the same process group.
    /// - Returns: `[ESMessage]` the list of `EXEC` events in the same process group, newest first.
    ///
    public func getProcGroup(message: ESMessage) -> [ESMessage] {
        let gid = message.event.exec?.target.group_id ?? message.process.group_id
        return execEvents(where: "exec_group_id", is: gid, group: "process group", of: message)
    }
    
    /// Get all `EXEC` events in a given process session.
    ///
    /// - Parameters:
    ///   - message: Provide a system event and we'll extract the `session_id` field to find the others in the same session.
    /// - Returns: `[ESMessage]` the list of `EXEC` events in the same process session, newest first.
    ///
    public func getProcSessionGroup(message: ESMessage) -> [ESMessage] {
        let sid = message.event.exec?.target.session_id ?? message.process.session_id
        return execEvents(where: "exec_session_id", is: sid, group: "session group", of: message)
    }
    
    /// The `EXEC` events whose target has `key` equal to `value`, found through the key's index on the view context.
    ///
    /// - Parameters:
    ///   - key: ``ESMessage/exec_group_id`` or ``ESMessage/exec_session_id``.
    ///   - value: The group or session to find.
    ///   - group: What's being looked up, for the log.
    ///   - message: The event the lookup is for, for the log.
    /// - Returns: The events, newest first.
    private func execEvents(where key: String, is value: Int32, group: String, of message: ESMessage) -> [ESMessage] {
        let request = ESMessage.fetchRequest()
        request.predicate = NSPredicate(format: "%K == %d", key, value)
        request.returnsObjectsAsFaults = false
        do {
            return try container.viewContext.fetch(request).sorted { $0.mach_time > $1.mach_time }
        } catch {
            CoreDataController.logger.error("Error obtaining \(group) for \(message.process.executable?.name ?? "") ==> \(message.es_event_type ?? "")")
            return []
        }
    }
    
    /// Construct a basic process tree given a target system event.
    ///
    /// We're calling `findParentProc` for the event, then for its parent, and so on, until no parent is found (or a
    /// process shows up twice).
    ///
    ///  - Parameters:
    ///    - targetEvent: The event (`ESMessage`) to find the parent process for
    ///    - tree: Ancestors already found, to continue from
    ///  - Returns: A list of system events: `[ESMessage]` the flat representation of the process tree, nearest parent first.
    ///
    public func getProcTree(targetEvent: ESMessage, tree: [ESMessage] = []) -> [ESMessage] {
        var tree = tree, current = targetEvent
        var seen: Set<NSManagedObjectID> = [targetEvent.objectID]
        while let parent = findParentProc(message: current), seen.insert(parent.objectID).inserted {
            tree.append(parent)
            current = parent
        }
        return tree
    }
    
    /// Find the parent process of a given system event
    ///
    /// Each `ESMessage` has an `initiating_process` we can attempt to find the corresponding `EXEC` and/or
    /// `FORK` event. What we're essentially doing here is looking for the event that created the process with the event's
    /// audit token: the indexed ``ESMessage/created_audit_token`` of an `EXEC` (preferred) or `FORK` event.
    ///
    /// - Parameters:
    ///   - message: The system event to try and find the parent process for
    /// - Returns: `ESMessage?`: The system event, if we can find it
    ///
    public func findParentProc(message: ESMessage) -> ESMessage? {
        guard message.process.audit_token != nil, let token = message.instigator_audit_token else { return nil }
        let request = ESMessage.fetchRequest()
        request.predicate = NSPredicate(format: "created_audit_token == %@ AND event_type IN %@", token, [ESMessage.execEventType, ESMessage.forkEventType])
        request.returnsObjectsAsFaults = false
        do {
            let creators = try container.viewContext.fetch(request)
            return creators.first { $0.event_type == ESMessage.execEventType } ?? creators.first { $0.event_type == ESMessage.forkEventType }
        } catch {
            CoreDataController.logger.error("We could not find the parent proc for: \(message.process.executable?.name ?? "")")
            return nil
        }
    }
    
    
    // MARK: - Telemetry export
    
    /// Export all system events to a file
    ///
    /// We can export all system events from the event store to either JSON or JSONL format. The events are streamed to
    /// the file in the background (see ``TelemetryExporter``), so recording carries on meanwhile.
    ///
    /// - Parameters:
    ///   - jsonl: Should we export the events line-by-line (one JSON object per line)?
    ///
    public func exportFullTrace(jsonl: Bool = false) {
        // UI work must be on the main thread.
        guard let telemetryFile = showSavePanel() else { return }
        export(to: telemetryFile, jsonl: jsonl, writeIfEmpty: true) { exporter, batch in try exporter.allEvents(through: batch) }
    }
    
    /// Export specified system events to a file, sorted by `mach_time`.
    ///
    /// The events are looked up and streamed to the file in the background (see ``TelemetryExporter``).
    ///
    /// - Parameters:
    ///   - eventIDs: A listing of the event `UUID`s we want to export.
    ///   - jsonl: Should we export the events line-by-line (one JSON object per line)?
    ///
    public func exportSelectedEvents(eventIDs: [UUID], jsonl: Bool = false) {
        // UI work must be on the main thread.
        guard let telemetryFile = showSavePanel(numberOfEvents: eventIDs.count) else { return }
        export(to: telemetryFile, jsonl: jsonl, writeIfEmpty: false) { exporter, _ in try exporter.events(withIDs: eventIDs) }
    }
    
    /// Exports in progress, so quitting can stop them before the store is deleted.
    private let exports = OSAllocatedUnfairLock(initialState: [ObjectIdentifier: TelemetryExporter]())
    
    /// Stream events to `url` in the background.
    ///
    /// The export starts once the inserts already queued have been saved, and covers the events saved up to then (the
    /// batch passed to `choose`): what it covered when it ran on `privateMOC`, without holding that queue while exporting.
    ///
    /// - Parameters:
    ///   - url: The destination, from the save panel.
    ///   - jsonl: JSONL (`true`) or pretty JSON (`false`).
    ///   - writeIfEmpty: Write an empty file when no events are chosen.
    ///   - choose: Picks the events, in file order, given the last ``ESMessage/insert_batch`` to cover.
    private func export(to url: URL, jsonl: Bool, writeIfEmpty: Bool,
                        choose: @escaping (TelemetryExporter, Int64) throws -> [NSManagedObjectID]) {
        let exporter = TelemetryExporter(container: container, pretty: !jsonl)
        let key = ObjectIdentifier(exporter)
        exports.withLock { $0[key] = exporter }
        privateMOC.perform {
            /// Saves and Clears queued after this block come after the snapshot.
            let batch = self.lastInsertBatch
            exporter.pin()
            exporter.run(to: url, writeIfEmpty: writeIfEmpty, choose: { try choose($0, batch) }) { result in
                self.exports.withLock { $0[key] = nil }
                if case .failure(let error) = result, !(error is CancellationError) {
                    CoreDataController.logger.error("Failed to export telemetry: \(error.localizedDescription, privacy: .public)")
                }
            }
        }
    }
    
    /// AppKit UI to save system traces.
    ///
    /// Show the `NSSavePanel`
    ///
    /// - Parameters:
    ///   - numberOfEvents: The number of events to save (to be displayed in the UI)
    ///
    ///  - Returns: `URL?`:  The optional URL to save the telemetry to
    ///
    public func showSavePanel(numberOfEvents: Int = 0) -> URL? {
        let savePanel = NSSavePanel()
        savePanel.allowedContentTypes = [UTType.json]
        savePanel.canCreateDirectories = true
        savePanel.isExtensionHidden = false
        savePanel.allowsOtherFileTypes = false
        savePanel.title = numberOfEvents == 0 ? "Save full system trace" : "Save \(numberOfEvents) events"
        savePanel.message = "Choose a directory to export the trace to"
        savePanel.nameFieldLabel = "Telemetry file name:"
        let response = savePanel.runModal()
        return response == .OK ? savePanel.url : nil
    }
}


// MARK: - Event store files
/// The event store's files on disk: one store per running Mac Monitor, each claimed with a lock.
///
/// Every process gets its own SQLite store in the caches folder and holds an exclusive `flock` on a `.lock` file beside it
/// for as long as it runs. A second copy of Mac Monitor (`open -n`, or a development build with the same bundle ID) gets a
/// store of its own instead of deleting the first one's trace. A store whose lock can be taken belongs to a process that
/// has quit or crashed, so it's deleted.
private struct EventStoreFile {
    /// The store's SQLite file.
    let url: URL
    
    private static let prefix = "Events"
    private static let storeSuffixes = [".sqlite", ".sqlite-wal", ".sqlite-shm"]
    
    /// Claim `Events.sqlite`, or a store of its own if another Mac Monitor has that one, then delete every store left by a
    /// process that's gone (including this store's, from a run that crashed).
    ///
    /// - Parameter directory: Mac Monitor's caches folder.
    /// - Returns: `nil` if no store could be claimed (for example, the folder can't be written).
    init?(in directory: URL) {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        guard let name = [Self.prefix, "\(Self.prefix)-\(UUID().uuidString)"].first(where: { Self.claim($0, in: directory) != nil }) else { return nil }
        url = directory.appendingPathComponent(name + ".sqlite")
        Self.removeStore(name, in: directory)
        
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        let stores = Set(names.compactMap { file in
            (Self.storeSuffixes + [".lock"]).first { file.hasPrefix(Self.prefix) && file.hasSuffix($0) }.map { String(file.dropLast($0.count)) }
        })
        for store in stores where store != name {
            /// Still claimed: another Mac Monitor is using it.
            guard let lock = Self.claim(store, in: directory) else { continue }
            Self.removeStore(store, in: directory)
            unlink(directory.appendingPathComponent(store + ".lock").path)
            close(lock)
        }
    }
    
    /// Delete this store's files, and its lock, at quit.
    ///
    /// Only the names go: the open connections keep working on the files until the process exits, so a save that lands
    /// meanwhile can't hit a store that's been taken away (which raises an exception Swift can't catch).
    func delete() {
        let directory = url.deletingLastPathComponent(), name = url.deletingPathExtension().lastPathComponent
        Self.removeStore(name, in: directory)
        unlink(directory.appendingPathComponent(name + ".lock").path)
    }
    
    /// Take the lock on store `name`, if no running process holds it.
    ///
    /// The lock is never released: the kernel drops it when the process exits.
    ///
    /// - Parameters:
    ///   - name: The store's name, without extension.
    ///   - directory: The caches folder.
    /// - Returns: The locked file descriptor, or `nil` if another process holds the lock (or it couldn't be taken).
    @discardableResult
    private static func claim(_ name: String, in directory: URL) -> Int32? {
        let path = directory.appendingPathComponent(name + ".lock").path
        let lock = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard lock >= 0 else { return nil }
        /// Another launch may have deleted the lock file between `open` and `flock`; a lock on a deleted file guards nothing.
        var held = stat(), current = stat()
        guard flock(lock, LOCK_EX | LOCK_NB) == 0, fstat(lock, &held) == 0, stat(path, &current) == 0,
              held.st_dev == current.st_dev, held.st_ino == current.st_ino else {
            close(lock)
            return nil
        }
        return lock
    }
    
    /// Delete store `name`'s SQLite files, if they exist.
    ///
    /// - Parameters:
    ///   - name: The store's name, without extension.
    ///   - directory: The caches folder.
    private static func removeStore(_ name: String, in directory: URL) {
        for suffix in storeSuffixes { unlink(directory.appendingPathComponent(name + suffix).path) }
    }
}
