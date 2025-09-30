//
//  ESODGroupRemoveEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/13/23.
//
//

import Foundation
import CoreData

@objc(ESODGroupRemoveEvent)
public class ESODGroupRemoveEvent: NSManagedObject, Decodable {
    enum CodingKeys: CodingKey {
        case id, instigator_process_name, instigator_process_path, instigator_process_audit_token, instigator_process_signing_id, error_code, group_name, member, node_name, db_path, error_code_human
    }
    
    convenience init(from message: Message) {
        let odRemoveGroupEvent: OpenDirectoryGroupRemoveEvent = message.event.od_group_remove!
        self.init()
        
        self.id = odRemoveGroupEvent.id
        self.instigator_process_name = odRemoveGroupEvent.instigator_process_name
        self.instigator_process_path = odRemoveGroupEvent.instigator_process_path
        self.instigator_process_audit_token = odRemoveGroupEvent.instigator_process_audit_token
        self.instigator_process_signing_id = odRemoveGroupEvent.instigator_process_signing_id
        
        self.error_code = Int32(odRemoveGroupEvent.error_code)
        self.group_name = odRemoveGroupEvent.group_name
        self.member = odRemoveGroupEvent.member
        self.node_name = odRemoveGroupEvent.node_name
        self.db_path = odRemoveGroupEvent.db_path
        self.error_code_human = odRemoveGroupEvent.error_code_human
    }
    
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let odRemoveGroupEvent: OpenDirectoryGroupRemoveEvent = message.event.od_group_remove!
        let description = NSEntityDescription.entity(forEntityName: "ESODGroupRemoveEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.id = odRemoveGroupEvent.id
        self.instigator_process_name = odRemoveGroupEvent.instigator_process_name
        self.instigator_process_path = odRemoveGroupEvent.instigator_process_path
        self.instigator_process_audit_token = odRemoveGroupEvent.instigator_process_audit_token
        self.instigator_process_signing_id = odRemoveGroupEvent.instigator_process_signing_id
        
        self.error_code = Int32(odRemoveGroupEvent.error_code)
        self.group_name = odRemoveGroupEvent.group_name
        self.member = odRemoveGroupEvent.member
        self.node_name = odRemoveGroupEvent.node_name
        self.db_path = odRemoveGroupEvent.db_path
        self.error_code_human = odRemoveGroupEvent.error_code_human
    }
    
    required convenience public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init()
        
        try id = container.decode(UUID.self, forKey: .id)
        try instigator_process_name = container.decode(String.self, forKey: .instigator_process_name)
        try instigator_process_path = container.decode(String.self, forKey: .instigator_process_path)
        try instigator_process_audit_token = container.decode(String.self, forKey: .instigator_process_audit_token)
        try instigator_process_signing_id = container.decode(String.self, forKey: .instigator_process_signing_id)
        
        try error_code = container.decode(Int32.self, forKey: .error_code)
        try group_name = container.decode(String.self, forKey: .group_name)
        try member = container.decode(String.self, forKey: .member)
        try node_name = container.decode(String.self, forKey: .node_name)
        try db_path = container.decode(String.self, forKey: .db_path)
        try error_code_human = container.decode(String.self, forKey: .error_code_human)
    }
}

extension ESODGroupRemoveEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(instigator_process_name, forKey: .instigator_process_name)
        try container.encode(instigator_process_path, forKey: .instigator_process_path)
        try container.encode(instigator_process_audit_token, forKey: .instigator_process_audit_token)
        try container.encode(instigator_process_signing_id, forKey: .instigator_process_signing_id)
        
        try container.encode(error_code, forKey: .error_code)
        try container.encode(group_name, forKey: .group_name)
        try container.encode(member, forKey: .member)
        try container.encode(node_name, forKey: .node_name)
        try container.encode(db_path, forKey: .db_path)
        try container.encode(error_code_human, forKey: .error_code_human)
    }
}

