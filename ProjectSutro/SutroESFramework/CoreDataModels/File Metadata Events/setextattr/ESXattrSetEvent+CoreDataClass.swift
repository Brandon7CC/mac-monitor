//
//  ESXattrSetEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//
//

import Foundation
import CoreData

@objc(ESXattrSetEvent)
public class ESXattrSetEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, target, extattr
    }
    
    
    // MARK: - Custom Core Data initilizer for ESXattrSetEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: XattrSetEvent = message.event.setextattr!
        let description = NSEntityDescription.entity(forEntityName: "ESXattrSetEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESXattrSetEvent.target))
        extattr = event.extattr
    }
}

// MARK: - Encodable conformance
extension ESXattrSetEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(extattr, forKey: .extattr)
    }
}
