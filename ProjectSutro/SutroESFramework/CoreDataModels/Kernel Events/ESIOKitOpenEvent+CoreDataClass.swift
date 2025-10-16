//
//  ESIOKitOpenEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//
//

import Foundation
import CoreData

@objc(ESIOKitOpenEvent)
public class ESIOKitOpenEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case user_client_class
        case user_client_type
        case parent_registry_id
        case parent_path
    }
    
    // MARK: - Custom Core Data initilizer for ESIOKitOpenEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let iokitEvent: IOKitOpenEvent = message.event.iokit_open!
        let description = NSEntityDescription.entity(forEntityName: "ESIOKitOpenEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.id = iokitEvent.id
        self.user_client_type = iokitEvent.user_client_type
        self.user_client_class = iokitEvent.user_client_class
        
        self.parent_registry_id = iokitEvent.parent_registry_id
        self.parent_path = iokitEvent.parent_path
    }
}

// MARK: - Encodable conformance
extension ESIOKitOpenEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(user_client_type, forKey: .user_client_type)
        try container.encode(user_client_class, forKey: .user_client_class)
        
        try container.encodeIfPresent(parent_path, forKey: .parent_path)
        if let _ = parent_path {
            try container.encode(parent_registry_id, forKey: .parent_registry_id)
        }
    }
}
