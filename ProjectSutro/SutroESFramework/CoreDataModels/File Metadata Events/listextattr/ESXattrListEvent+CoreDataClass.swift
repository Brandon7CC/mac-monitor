//
//  ESXattrListEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/19/25.
//
//

import Foundation
import CoreData

@objc(ESXattrListEvent)
public class ESXattrListEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESFile

    enum CodingKeys: CodingKey {
        case target
    }
    
    
    // MARK: - Custom Core Data initilizer for ESXattrListEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: XattrListEvent = message.event.listextattr!
        let description = NSEntityDescription.entity(forEntityName: "ESXattrListEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESXattrListEvent.target))
    }
}

// MARK: - Encodable conformance
extension ESXattrListEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
    }
}
