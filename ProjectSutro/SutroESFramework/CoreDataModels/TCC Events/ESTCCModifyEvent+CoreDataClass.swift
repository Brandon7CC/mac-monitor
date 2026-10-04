//
//  ESTCCModifyEvent+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/15/25.
//
//

import Foundation
import CoreData


@objc(ESTCCModifyEvent)
public class ESTCCModifyEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        
        case service
        case identity
        case identity_type
        case identity_type_string
        case update_type
        case update_type_string
        case instigator_token
        case instigator
        case responsible_token
        case responsible
        case right
        case right_string
        case reason
        case reason_string
    }
    
    // MARK: - Custom Core Data initilizer for ESTCCModifyEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let tccModifyEvent: TCCModifyEvent = message.event.tcc_modify!
        let description = NSEntityDescription.entity(forEntityName: "ESTCCModifyEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = tccModifyEvent.id
        
        self.service = tccModifyEvent.service
        self.identity = tccModifyEvent.identity
        self.identity_type = Int32(truncatingIfNeeded: tccModifyEvent.identity_type)
        self.identity_type_string = tccModifyEvent.identity_type_string
        self.update_type = Int32(truncatingIfNeeded: tccModifyEvent.update_type)
        self.update_type_string = tccModifyEvent.update_type_string
        
        self.instigator_token = ESAuditToken(
            from: tccModifyEvent.instigator_token,
            insertIntoManagedObjectContext: context
        )
        if let instigator = tccModifyEvent.instigator {
            self.instigator = ESProcess(
                from: instigator,
                version: message.version,
                insertIntoManagedObjectContext: context
            )
        }
        
        if let responsibleToken = tccModifyEvent.responsible_token,
           let responsible = tccModifyEvent.responsible {
            self.responsible_token = ESAuditToken(
                from: responsibleToken,
                insertIntoManagedObjectContext: context
            )
            self.responsible = ESProcess(
                from: responsible,
                version: message.version,
                insertIntoManagedObjectContext: context
            )
        }
        
        self.right = Int32(truncatingIfNeeded: tccModifyEvent.right)
        self.right_string = tccModifyEvent.right_string
        self.reason = Int32(truncatingIfNeeded: tccModifyEvent.reason)
        self.reason_string = tccModifyEvent.reason_string
    }
}

// MARK: - Encodable conformance
extension ESTCCModifyEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(id, forKey: .id)
        
        try container.encode(service, forKey: .service)
        try container.encode(identity, forKey: .identity)
        try container.encode(identity_type, forKey: .identity_type)
        try container.encode(identity_type_string, forKey: .identity_type_string)
        try container.encode(update_type, forKey: .update_type)
        try container.encode(update_type_string, forKey: .update_type_string)
        
        try container.encode(instigator_token, forKey: .instigator_token)
        try container.encode(instigator, forKey: .instigator)
        
        try container.encode(responsible_token, forKey: .responsible_token)
        try container.encode(responsible, forKey: .responsible)
        
        try container.encode(right, forKey: .right)
        try container.encode(right_string, forKey: .right_string)
        try container.encode(reason, forKey: .reason)
        try container.encode(reason_string, forKey: .reason_string)
    }
}
