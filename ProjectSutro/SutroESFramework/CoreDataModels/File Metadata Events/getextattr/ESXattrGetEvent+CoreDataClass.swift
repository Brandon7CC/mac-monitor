//
//  ESXattrGetEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/25.
//
//

import Foundation
import CoreData

@objc(ESXattrGetEvent)
public class ESXattrGetEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, target, extattr
    }
    
    
    // MARK: - Custom Core Data initilizer for ESXattrGetEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: XattrGetEvent = message.event.getextattr!
        let description = NSEntityDescription.entity(forEntityName: "ESXattrGetEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESXattrGetEvent.target))
        extattr = event.extattr
    }
}

// MARK: - Encodable conformance
extension ESXattrGetEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(extattr, forKey: .extattr)
    }
}
