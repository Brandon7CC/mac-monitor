//
//  ESODGroupAddEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/13/23.
//
//

import Foundation
import CoreData


@objc(ESODGroupAddEvent)
public class ESODGroupAddEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, instigator_process_name, instigator_process_path, instigator_process_audit_token, instigator_process_signing_id, error_code, group_name, member, node_name, db_path, error_code_human
    }
    
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let odAddGroupEvent: OpenDirectoryGroupAddEvent = message.event.od_group_add!
        let description = NSEntityDescription.entity(forEntityName: "ESODGroupAddEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.id = odAddGroupEvent.id
        self.instigator_process_name = odAddGroupEvent.instigator_process_name
        self.instigator_process_path = odAddGroupEvent.instigator_process_path
        self.instigator_process_audit_token = odAddGroupEvent.instigator_process_audit_token
        self.instigator_process_signing_id = odAddGroupEvent.instigator_process_signing_id
        
        self.error_code = Int32(truncatingIfNeeded: odAddGroupEvent.error_code)
        self.group_name = odAddGroupEvent.group_name
        self.member = odAddGroupEvent.member
        self.node_name = odAddGroupEvent.node_name
        self.db_path = odAddGroupEvent.db_path
        self.error_code_human = odAddGroupEvent.error_code_human
    }
}

extension ESODGroupAddEvent: Encodable {
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
