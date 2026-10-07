//
//  CoreDataController+LaunchedByParent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import CoreData


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
