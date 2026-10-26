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
public class ESTCCModifyEvent: NSManagedObject, Identifiable {
    @NSManaged public var service: String
    @NSManaged public var identity: String
    @NSManaged public var identity_type: Int32
    @NSManaged public var update_type: Int32
    @NSManaged public var right: Int32
    @NSManaged public var reason: Int32
    @NSManaged public var identity_type_string: String
    @NSManaged public var update_type_string: String
    @NSManaged public var right_string: String
    @NSManaged public var reason_string: String
    
    @NSManaged public var instigator_token: ESAuditToken?
    @NSManaged public var instigator: ESProcess?
    
    @NSManaged public var responsible_token: ESAuditToken?
    @NSManaged public var responsible: ESProcess?

    enum CodingKeys: CodingKey {
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
    convenience init(from event: TCCModifyEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.service = event.service
        self.identity = event.identity
        self.identity_type = Int32(truncatingIfNeeded: event.identity_type)
        self.identity_type_string = event.identity_type_string
        self.update_type = Int32(truncatingIfNeeded: event.update_type)
        self.update_type_string = event.update_type_string
        
        self.instigator_token = ESAuditToken(
            from: event.instigator_token,
            insertIntoManagedObjectContext: context
        )
        self.instigator = event.instigator.map {
            ESProcess(from: $0, version: message.version, insertIntoManagedObjectContext: context)
        }
        
        /// The responsible token and process on their own: Endpoint Security can leave out the process (`NULL`) and
        /// still give its token.
        self.responsible_token = event.responsible_token.map {
            ESAuditToken(from: $0, insertIntoManagedObjectContext: context)
        }
        self.responsible = event.responsible.map {
            ESProcess(from: $0, version: message.version, insertIntoManagedObjectContext: context)
        }
        
        self.right = Int32(truncatingIfNeeded: event.right)
        self.right_string = event.right_string
        self.reason = Int32(truncatingIfNeeded: event.reason)
        self.reason_string = event.reason_string
    }
}

// MARK: - Encodable conformance
extension ESTCCModifyEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
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
