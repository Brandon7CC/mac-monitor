//
//  ESProcessForkEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData

@objc(ESProcessForkEvent)
public class ESProcessForkEvent: NSManagedObject, Identifiable, LaunchedByParentColumns {
    /// The child process. The row may be shared with the events the child goes on to cause.
    @NSManaged public var child: ESProcess
    /// The `id` ``child`` had in this event (and exports). A shared row keeps the `id` of the first event that
    /// stored it.
    @NSManaged public var child_id: UUID?
    /// ``launched_by_parent``, in plain columns (``LaunchedByParentColumns``).
    @NSManaged public var launched_by_parent_source, launched_by_parent_resolved_by: String?
    @NSManaged public var launched_by_parent_path, launched_by_parent_job: String?
    @NSManaged public var launched_by_parent_pid: NSNumber?
    @NSManaged public var launched_by_parent_token: Data?

    enum CodingKeys: CodingKey {
        case child, launched_by_parent
    }
    
    /// Mac Monitor's launched-by parent of ``child`` (``LaunchedByParent``), kept in plain columns
    /// (``LaunchedByParentColumns``). `nil` until it's resolved.
    public var launched_by_parent: LaunchedByParent? {
        get { storedLaunchedByParent }
        set { storedLaunchedByParent = newValue }
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessForkEvent
    convenience init(from event: ProcessForkEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        /// The child: shared with the events it goes on to cause (see ``ESProcess/row(for:version:in:)``).
        attach(
            ESProcess.row(for: event.child, version: message.version, in: context),
            to: #keyPath(ESProcessForkEvent.child)
        )
        self.child_id = event.child.id
        self.launched_by_parent = event.launched_by_parent
    }
}

// MARK: - Encodable conformance
extension ESProcessForkEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ESProcessRecord(process: child, id: child_id ?? child.id), forKey: .child)
        /// Mac Monitor's enrichment beside eslogger's fields: `null` when there's none, so the key is always there.
        try container.encode(launched_by_parent, forKey: .launched_by_parent)
    }
}
