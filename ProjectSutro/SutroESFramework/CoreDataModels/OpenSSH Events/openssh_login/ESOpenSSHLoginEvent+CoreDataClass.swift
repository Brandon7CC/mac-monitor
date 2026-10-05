//
//  ESOpenSSHLoginEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 12/14/22.
//
//

import Foundation
import CoreData

@objc(ESOpenSSHLoginEvent)
public class ESOpenSSHLoginEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case success
        case result_type
        case result_type_string
        case source_address_type
        case source_address_type_string
        case source_address
        case username
        case has_uid
        case uid
    }

    // MARK: - Custom Core Data initilizer for ESOpenSSHLoginEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: SSHLoginEvent = message.event.openssh_login!
        let description = NSEntityDescription.entity(forEntityName: "ESOpenSSHLoginEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        self.success = event.success
        self.result_type = event.result_type
        self.result_type_string = event.result_type_string
        
        self.source_address_type = event.source_address_type
        self.source_address_type_string = event.source_address_type_string
        self.source_address = event.source_address
        
        self.username = event.username
        
        self.has_uid = event.has_uid
        self.uid = event.uid ?? -1
    }
}

// MARK: - Encodable conformance
extension ESOpenSSHLoginEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(id, forKey: .id)
        
        try container.encode(success, forKey: .success)
        try container.encode(result_type, forKey: .result_type)
        try container.encode(result_type_string, forKey: .result_type_string)
        
        try container.encode(source_address_type, forKey: .source_address_type)
        try container.encode(source_address_type_string, forKey: .source_address_type_string)
        try container.encode(source_address, forKey: .source_address)
        
        try container.encode(username, forKey: .username)
        
        try container.encode(has_uid, forKey: .has_uid)
        /// eslogger writes `null` without a uid; the stored -1 only marks its absence. A `uid_t`, kept by bit pattern:
        /// written unsigned, as eslogger writes it.
        try container.encode(has_uid ? UInt32(bitPattern: uid) : nil, forKey: .uid)
    }
}
