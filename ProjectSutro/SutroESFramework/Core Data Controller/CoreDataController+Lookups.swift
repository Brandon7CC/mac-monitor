//
//  CoreDataController+Lookups.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import CoreData
import OSLog


extension CoreDataController {
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
}
