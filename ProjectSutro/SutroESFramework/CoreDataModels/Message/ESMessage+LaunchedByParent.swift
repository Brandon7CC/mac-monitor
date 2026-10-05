//
//  ESMessage+LaunchedByParent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import CoreData


// MARK: - Launched by parent
extension ESMessage {
    /// Did this event create a process? An exec (its target) and a fork (its child) do.
    public var createsProcess: Bool {
        event_type == Self.execEventType || event_type == Self.forkEventType
    }
    
    /// The launched-by parent of the process this event created (an exec's target or a fork's child), as stored. `nil`
    /// for any other event, and for one without an answer.
    public var createdLaunchedByParent: LaunchedByParent? {
        switch event_type {
        case Self.execEventType: event.exec?.launched_by_parent
        case Self.forkEventType: event.fork?.launched_by_parent
        default: nil
        }
    }
    
    /// Give a stored exec the launched-by parent Mac Monitor found for its target after storing it (LaunchServices'
    /// answer, ``LaunchedByParentUpgrader``): its ``ESProcessExecEvent/launched_by_parent``. Nothing is saved.
    ///
    /// - Parameters:
    ///   - launchedByParent: The launched-by parent.
    ///   - id: The exec's ``id``, found through its index.
    ///   - context: The context to find and change the exec in. Call on its queue.
    /// - Returns: The exec, or `nil` when the context has no exec with that `id` (any other event is left alone).
    @discardableResult
    static func applyLaunchedByParent(_ launchedByParent: LaunchedByParent, toEventWithID id: UUID,
                                      in context: NSManagedObjectContext) -> ESMessage? {
        let request = fetchRequest()
        request.predicate = NSPredicate(format: "id == %@ AND event_type == %d", id as CVarArg, execEventType)
        request.fetchLimit = 1
        guard let message = (try? context.fetch(request))?.first, let exec = message.event.exec else { return nil }
        exec.launched_by_parent = launchedByParent
        return message
    }
}
