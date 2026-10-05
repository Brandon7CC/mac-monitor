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
public class ESProcessForkEvent: NSManagedObject {
    
    enum CodingKeys: CodingKey {
        case id, child, launched_by_parent
    }
    
    /// Mac Monitor's launched-by parent of ``child`` (``LaunchedByParent``), kept in plain columns
    /// (``LaunchedByParentColumns``). `nil` until it's resolved.
    public var launched_by_parent: LaunchedByParent? {
        get { storedLaunchedByParent }
        set { storedLaunchedByParent = newValue }
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessForkEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let forkEvent: ProcessForkEvent = message.event.fork!
        let description = NSEntityDescription.entity(forEntityName: "ESProcessForkEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = forkEvent.id
        
        /// The child: shared with the events it goes on to cause (see ``ESProcess/row(for:version:in:)``).
        attach(ESProcess.row(for: forkEvent.child, version: message.version, in: context), to: #keyPath(ESProcessForkEvent.child))
        self.child_id = forkEvent.child.id
        self.launched_by_parent = forkEvent.launched_by_parent
    }
}

// MARK: - Encodable conformance
extension ESProcessForkEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ESProcessRecord(process: child, id: child_id ?? child.id), forKey: .child)
        /// Mac Monitor's addition beside eslogger's fields: `null` when there's none, so the key is always there.
        try container.encode(launched_by_parent, forKey: .launched_by_parent)
    }
}
