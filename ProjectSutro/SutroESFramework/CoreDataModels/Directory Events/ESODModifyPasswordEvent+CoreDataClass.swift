//
//  ESODModifyPasswordEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//
//

import Foundation
import CoreData

@objc(ESODModifyPasswordEvent)
public class ESODModifyPasswordEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, instigator_process_name, instigator_process_path, instigator_process_audit_token, instigator_process_signing_id, error_code, account_type, account_name, node_name, db_path, error_code_human
    }
    
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let odModifyPasswordEvent: OpenDirectoryModifyPasswordEvent = message.event.od_modify_password!
        let description = NSEntityDescription.entity(forEntityName: "ESODModifyPasswordEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.id = odModifyPasswordEvent.id
        self.instigator_process_name = odModifyPasswordEvent.instigator_process_name
        self.instigator_process_path = odModifyPasswordEvent.instigator_process_path
        self.instigator_process_audit_token = odModifyPasswordEvent.instigator_process_audit_token
        self.instigator_process_signing_id = odModifyPasswordEvent.instigator_process_signing_id
        
        self.error_code = Int32(truncatingIfNeeded: odModifyPasswordEvent.error_code)
        self.account_type = odModifyPasswordEvent.account_type
        self.account_name = odModifyPasswordEvent.account_name
        self.node_name = odModifyPasswordEvent.node_name
        self.db_path = odModifyPasswordEvent.db_path
        self.error_code_human = odModifyPasswordEvent.error_code_human
    }
}

extension ESODModifyPasswordEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(instigator_process_name, forKey: .instigator_process_name)
        try container.encode(instigator_process_path, forKey: .instigator_process_path)
        try container.encode(instigator_process_audit_token, forKey: .instigator_process_audit_token)
        try container.encode(instigator_process_signing_id, forKey: .instigator_process_signing_id)
        
        try container.encode(error_code, forKey: .error_code)
        try container.encode(account_type, forKey: .account_type)
        try container.encode(account_name, forKey: .account_name)
        try container.encode(node_name, forKey: .node_name)
        try container.encode(db_path, forKey: .db_path)
        try container.encode(error_code_human, forKey: .error_code_human)
    }
}
