//
//  CoreDataController+LaunchedByParent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import CoreData


// MARK: - Updating a launched-by parent
extension CoreDataController {
    /// Give a stored exec the launched-by parent Mac Monitor found for its target after storing it: LaunchServices'
    /// answer, which can arrive after the exec's batch has left ``EndpointSecurityManager``'s buffer.
    ///
    /// It runs on the private context's queue, behind every insert queued before it, so the exec's own insert comes
    /// first and the exec is found whether or not its save succeeded. ``LaunchedByParentStoreUpdate`` saves it and
    /// shows it to the view context.
    ///
    /// - Parameters:
    ///   - eventID: The exec's `id`.
    ///   - launchedByParent: The launched-by parent of its target.
    func updateLaunchedByParent(eventID: UUID, to launchedByParent: LaunchedByParent) {
        privateMOC.perform {
            LaunchedByParentStoreUpdate(context: self.privateMOC, viewContext: self.container.viewContext)
                .apply(launchedByParent, toEventWithID: eventID, canSave: self.canSave.withLock { $0 },
                       hasUnsavedEvents: self.hasUnsavedEvents)
        }
    }
}


// MARK: - A stored exec's update
/// Gives a stored exec a launched-by parent found after it was stored, in the context events are inserted in, and shows
/// the change to the context the UI reads.
///
/// The change is saved at once. When a failed save has left events unsaved, only an insert's save may store them (and
/// announce them, ``CoreDataController/eventsInserted``), so the change rides along with the next insert's. A change
/// whose own save fails is rolled back: the store keeps the earlier answer. Nothing is kept afterwards: the insert
/// context doesn't hold on to saved objects.
///
/// The view context doesn't merge saves while the event tables are up (they turn its automatic merging off), so a
/// saved change refreshes the exec there, only when the view context already has it: nothing new is loaded on the main
/// queue. A change that rides along with an insert's save isn't refreshed.
struct LaunchedByParentStoreUpdate {
    /// What an update did.
    enum Outcome: Equatable {
        /// Nothing: there's no store, or Mac Monitor is quitting.
        case notSaving
        /// Nothing: the context has no exec with that `id`.
        case notFound
        /// Applied, to be saved with the next insert's save.
        case deferred
        /// Applied and saved, and the view context's exec refreshed.
        case saved
        /// Applied, but its save failed, so it was rolled back.
        case rolledBack
    }
    
    /// The context events are inserted in. Apply updates on its queue.
    let context: NSManagedObjectContext
    /// The context the UI reads, if any.
    let viewContext: NSManagedObjectContext?
    
    /// Give a stored exec a launched-by parent, and save it unless events are waiting for an insert's save.
    ///
    /// - Parameters:
    ///   - launchedByParent: The launched-by parent of the exec's target.
    ///   - id: The exec's `id`.
    ///   - canSave: Can the store save (``CoreDataController/canSave``)?
    ///   - hasUnsavedEvents: Has a failed save left events unsaved (``CoreDataController/hasUnsavedEvents``)?
    /// - Returns: What the update did.
    @discardableResult
    func apply(_ launchedByParent: LaunchedByParent, toEventWithID id: UUID, canSave: Bool,
               hasUnsavedEvents: Bool) -> Outcome {
        guard canSave else { return .notSaving }
        let message = ESMessage.applyLaunchedByParent(launchedByParent, toEventWithID: id, in: context)
        guard let exec = message?.event.exec else { return .notFound }
        guard !hasUnsavedEvents else { return .deferred }
        do {
            try context.save()
        } catch {
            CoreDataController.logger.error("Error saving a launched-by parent: \(error.localizedDescription)")
            context.rollback()
            return .rolledBack
        }
        refreshInViewContext(exec.objectID)
        return .saved
    }
    
    /// Refresh an object from the store in the view context, if the view context has it.
    ///
    /// - Parameter id: The object's ID.
    private func refreshInViewContext(_ id: NSManagedObjectID) {
        guard let viewContext else { return }
        viewContext.perform {
            guard let object = viewContext.registeredObject(for: id) else { return }
            viewContext.refresh(object, mergeChanges: true)
        }
    }
}


// MARK: - Reading launched-by parents
extension CoreDataController {
    /// The launched-by parents of the process an event is about, nearest first, from the view context (call on the main
    /// thread): its launched-by parent, that parent's, and so on, each with the event that created it when the store
    /// has it.
    ///
    /// An exec or fork is about the process it created (its target or child); any other event is about the process
    /// that caused it. The walk ends after launchd, at a parent the store doesn't have, at a LaunchServices answer
    /// that names no launcher, at a parent already walked, or after 64 steps.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - limit: The most steps to return (never more than 64): `1` for just the launched-by parent.
    /// - Returns: The steps, nearest first. Empty when the store doesn't have the event that created the process.
    public func launchedByParents(of event: ESMessage, limit: Int = .max) -> [LaunchedByParentStep] {
        LineageLookup(container.viewContext).launchedByParents(of: event, limit: limit)
    }
    
    /// The Unix parent and the launched-by parent of the process an exec or fork created, from the view context (call
    /// on the main thread).
    ///
    /// - Parameter event: The exec or fork.
    /// - Returns: Its parents, or `nil` for any other event.
    public func parents(of event: ESMessage) -> ProcessParents? {
        LineageLookup(container.viewContext).parents(of: event)
    }
}
