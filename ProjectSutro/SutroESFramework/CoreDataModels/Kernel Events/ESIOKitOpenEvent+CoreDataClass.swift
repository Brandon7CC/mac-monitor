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
        
        /// Message version 10 and later: before it, Endpoint Security has no such fields and eslogger writes neither.
        if message.version >= 10 {
            self.has_parent_fields = true
            self.parent_registry_id = iokitEvent.parent_registry_id.map { NSNumber(value: $0) }
            self.parent_path = iokitEvent.parent_path
        }
    }
    
    /// The parent's IOKit registry ID, unsigned as Endpoint Security gives it, or `nil` before message version 10 or
    /// when the record had none.
    public var parentRegistryID: UInt64? {
        parent_registry_id.map { UInt64(bitPattern: $0.int64Value) }
    }
}

// MARK: - Encodable conformance
extension ESIOKitOpenEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(user_client_type, forKey: .user_client_type)
        try container.encode(user_client_class, forKey: .user_client_class)
        
        /// Message version 10 (macOS 26) and later only, as eslogger writes them: both keys, or neither. A value the
        /// record didn't have is `null`, never made up.
        if has_parent_fields {
            try container.encode(parent_path, forKey: .parent_path)
            try container.encode(parentRegistryID, forKey: .parent_registry_id)
        }
    }
}
