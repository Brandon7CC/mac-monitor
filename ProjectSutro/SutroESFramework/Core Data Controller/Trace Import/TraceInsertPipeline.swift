//
//  TraceInsertPipeline.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation
import CoreData


// MARK: - Trace insert pipeline
/// Builds a trace's batches into objects on the importer's queue while the batch before saves.
///
/// Recording builds and saves each batch on `privateMOC`, one after the other
/// (``CoreDataController/insertSystemEvents(messages:completion:)``). On a trace that queue spent about 40% of its time
/// building objects. Here each batch is built in one of two contexts while the other context's batch saves. So
/// `privateMOC` only saves.
///
/// A batch's rows get permanent IDs as soon as it's built (`obtainPermanentIDs`). So the next batch, built in the other
/// context, can share them through ``EventRowCaches`` before they're saved. Saves run in batch order, so a shared row
/// is always saved before or with its first user.
///
/// The save, the insert order and batch, and ``CoreDataController/eventsInserted`` stay on `privateMOC`'s queue. They
/// stay in order with Clears and exports. A Clear closes ``CoreDataController/traceBuildGate`` while it replaces the
/// store, so a build never runs against a store that's gone. A batch built for a closed trace is dropped.
///
/// Only used on the importer's queue, one batch at a time.
final class TraceInsertPipeline {
    /// A batch built and waiting to be saved.
    struct Built {
        let context: NSManagedObjectContext
        let events: [ESMessage]
    }

    /// What building a batch did.
    enum Outcome {
        /// Built, to be saved.
        case built(Built)
        /// Not built, because the trace has been closed.
        case closed
        /// Not built, because its rows couldn't be given IDs (the disk is full).
        case failed
    }

    /// The two contexts batches are built in, in turn.
    private let contexts: [NSManagedObjectContext]
    /// The rows this trace's events share, across both contexts.
    private let rowCaches = EventRowCaches()
    /// The next context to build in.
    private var turn = 0
    private unowned let store: CoreDataController
    private let clear: Int

    /// - Parameters:
    ///   - store: The event store.
    ///   - clear: The Clear that opened the trace.
    init(store: CoreDataController, clear: Int) {
        self.store = store
        self.clear = clear
        contexts = (0..<2).map { _ in
            let context = store.container.newBackgroundContext()
            context.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy
            context.retainsRegisteredObjects = false
            context.undoManager = nil
            return context
        }
        for context in contexts { context.performAndWait { context.userInfo[EventRowCaches.userInfoKey] = rowCaches } }
    }

    /// Build a batch in the next context. Call only once the batch built two calls ago has been saved or dropped.
    ///
    /// - Parameter messages: The events, in file order.
    /// - Returns: The batch, or why there's none.
    func build(_ messages: [Message]) -> Outcome {
        let context = contexts[turn]
        turn ^= 1
        let outcome = store.traceBuildGate.ifOpen(for: clear) {
            context.performAndWait { () -> Outcome in
                let events = messages.map { ESMessage(storing: $0, order: 0, in: context) }
                do {
                    try context.obtainPermanentIDs(for: Array(context.insertedObjects))
                } catch {
                    context.reset()
                    rowCaches.forget()
                    return .failed
                }
                /// The new rows now have permanent IDs, so the next batch shares them too.
                rowCaches.didSave()
                return .built(Built(context: context, events: events))
            }
        }
        return outcome ?? .closed
    }

    /// Drop a batch that won't be saved.
    ///
    /// - Parameter built: The batch.
    func discard(_ built: Built) {
        built.context.performAndWait { built.context.reset() }
    }
}


// MARK: - Build gate
/// Keeps a Clear and a trace's batch build from running at once.
///
/// A Clear closes the gate while it takes the store away. A build runs only while the gate is open, and only for the
/// trace of the last Clear.
final class TraceBuildGate {
    private let lock = NSLock()
    /// The last Clear to close the gate.
    private var clear = 0

    /// Close the gate for a Clear. Waits for a build in progress to finish. Call ``open()`` on the same thread once the
    /// store is replaced.
    ///
    /// - Parameter clear: The Clear's number.
    func close(for clear: Int) {
        lock.lock()
        self.clear = clear
    }

    /// Open the gate that ``close(for:)`` closed.
    func open() {
        lock.unlock()
    }

    /// Run a build unless a Clear has come after the one that opened its trace.
    ///
    /// - Parameters:
    ///   - clear: The Clear that opened the trace.
    ///   - body: The build.
    /// - Returns: What `body` returned, or `nil` once the trace is closed.
    func ifOpen<T>(for clear: Int, _ body: () -> T) -> T? {
        lock.lock()
        defer { lock.unlock() }
        return self.clear == clear ? body() : nil
    }
}


// MARK: - Saving a built batch
extension CoreDataController {
    /// Save a batch built by ``TraceInsertPipeline`` on `privateMOC`'s queue, and announce it (``eventsInserted``).
    ///
    /// It does what ``insertTraceEvents(_:clear:completion:)`` does with a batch it builds itself.
    ///
    /// - Parameters:
    ///   - built: The batch.
    ///   - clear: The Clear that opened the trace. Once another Clear has run, the batch is dropped.
    ///   - completion: Called on the private context's queue with whether the batch was saved. A batch dropped for a
    ///     closed trace counts as saved, as in ``insertTraceEvents(_:clear:completion:)``.
    func saveTraceEvents(_ built: TraceInsertPipeline.Built, clear: Int, completion: @escaping (Bool) -> Void) {
        privateMOC.perform {
            var saved = false
            defer { completion(saved) }
            let context = built.context
            guard self.canSave.withLock({ $0 }) else { return context.performAndWait { context.reset() } }
            guard clear == self.currentClear else {
                saved = true
                return context.performAndWait { context.reset() }
            }
            let batch = self.lastInsertBatch + 1
            var order = self.nextInsertOrder
            let ids: [NSManagedObjectID]? = context.performAndWait {
                defer { context.reset() }
                for event in built.events {
                    event.insert_order = order
                    event.insert_batch = batch
                    order += 1
                }
                do {
                    try context.save()
                    return built.events.map(\.objectID)
                } catch {
                    CoreDataController.logger.error("Error saving a trace's batch: \(error.localizedDescription)")
                    return nil
                }
            }
            self.nextInsertOrder = order
            guard let ids else { return }
            saved = true
            self.savedBatch.withLock { $0 = batch }
            NotificationCenter.default.post(name: Self.eventsInserted, object: self,
                                            userInfo: [Self.insertedObjectIDsKey: ids, Self.insertBatchKey: batch])
        }
    }
}
