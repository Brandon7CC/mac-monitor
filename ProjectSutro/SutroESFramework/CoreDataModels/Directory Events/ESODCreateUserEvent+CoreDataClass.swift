//
//  ESODCreateUserEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//
//

import Foundation
import CoreData


/// Models an [`es_event_od_create_user_t`](https://developer.apple.com/documentation/endpointsecurity/3228936-es_events_t/4161233-od_create_user)  which
/// is emitted when a user is added to an Open Directory node.
///
///
@objc(ESODCreateUserEvent)
public class ESODCreateUserEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, instigator_process_name, instigator_process_path, instigator_process_audit_token, instigator_process_signing_id, error_code, user_name, node_name, db_path, error_code_human
    }
    
    // MARK: - Custom Core Data initilizer for ESODCreateUserEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let odCreateUserEvent: OpenDirectoryCreateUserEvent = message.event.od_create_user!
        let description = NSEntityDescription.entity(forEntityName: "ESODCreateUserEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.id = odCreateUserEvent.id
        self.instigator_process_name = odCreateUserEvent.instigator_process_name
        self.instigator_process_path = odCreateUserEvent.instigator_process_path
        self.instigator_process_audit_token = odCreateUserEvent.instigator_process_audit_token
        self.instigator_process_signing_id = odCreateUserEvent.instigator_process_signing_id
        
        self.error_code = Int32(truncatingIfNeeded: odCreateUserEvent.error_code)
        self.user_name = odCreateUserEvent.user_name
        self.node_name = odCreateUserEvent.node_name
        self.db_path = odCreateUserEvent.db_path
        self.error_code_human = odCreateUserEvent.error_code_human
    }
}

// MARK: - Encodable conformance
extension ESODCreateUserEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(instigator_process_name, forKey: .instigator_process_name)
        try container.encode(instigator_process_path, forKey: .instigator_process_path)
        try container.encode(instigator_process_audit_token, forKey: .instigator_process_audit_token)
        try container.encode(instigator_process_signing_id, forKey: .instigator_process_signing_id)
        
        try container.encode(error_code, forKey: .error_code)
        try container.encode(user_name, forKey: .user_name)
        try container.encode(node_name, forKey: .node_name)
        try container.encode(db_path, forKey: .db_path)
        try container.encode(error_code_human, forKey: .error_code_human)
    }
}
