//
//  ESXattrDeleteEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData

@objc(ESXattrDeleteEvent)
public class ESXattrDeleteEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, target, extattr
    }
    
    // MARK: - Custom Core Data initilizer for ESXattrDeleteEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: XattrDeleteEvent = message.event.deleteextattr!
        let description = NSEntityDescription.entity(forEntityName: "ESXattrDeleteEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESXattrDeleteEvent.target))
        extattr = event.extattr
    }
}

// MARK: - Encodable conformance
extension ESXattrDeleteEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(extattr, forKey: .extattr)
    }
}
