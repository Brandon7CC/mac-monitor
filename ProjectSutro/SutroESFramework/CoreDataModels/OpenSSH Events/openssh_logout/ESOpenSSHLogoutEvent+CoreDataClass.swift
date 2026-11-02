//
//  ESOpenSSHLogoutEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//
//

import Foundation
import CoreData

@objc(ESOpenSSHLogoutEvent)
public class ESOpenSSHLogoutEvent: NSManagedObject, Identifiable {
    @NSManaged public var source_address_type: Int32
    @NSManaged public var source_address_type_string: String
    @NSManaged public var source_address: String
    @NSManaged public var username: String
    
    @NSManaged public var uid: Int32

    enum CodingKeys: CodingKey {
        case source_address_type
        case source_address_type_string
        case source_address
        case username
        case uid
    }
    
    // MARK: - Custom Core Data initilizer for ESOpenSSHLogoutEvent
    convenience init(from event: SSHLogoutEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.source_address_type = event.source_address_type
        self.source_address_type_string = event.source_address_type_string
        self.source_address = event.source_address
        self.username = event.username
        self.uid = event.uid
    }
}

// MARK: - Encodable conformance
extension ESOpenSSHLogoutEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(source_address_type, forKey: .source_address_type)
        try container.encode(source_address_type_string, forKey: .source_address_type_string)
        try container.encode(source_address, forKey: .source_address)
        try container.encode(username, forKey: .username)
        /// A `uid_t`, kept by bit pattern: written unsigned, as eslogger writes it.
        try container.encode(UInt32(bitPattern: uid), forKey: .uid)
    }
}
