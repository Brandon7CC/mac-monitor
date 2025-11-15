//
//  ESMProtectEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/14/25.
//
//

import Foundation
import CoreData

@objc(ESMProtectEvent)
public class ESMProtectEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case protection
        case address
        case size
    }
    
    // MARK: - Custom Core Data initilizer for ESMProtectEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: MProtectEvent = message.event.mprotect!
        let description = NSEntityDescription.entity(forEntityName: "ESMProtectEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        self.protection = event.protection
        self.address = event.address
        self.size = event.size
    }
}

// MARK: - Encodable conformance
extension ESMProtectEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(protection, forKey: .protection)
    }
}
