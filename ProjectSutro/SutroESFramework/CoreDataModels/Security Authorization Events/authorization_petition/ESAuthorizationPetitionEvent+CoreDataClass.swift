//
//  ESAuthorizationPetitionEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/27/23.
//
//

import Foundation
import CoreData

@objc(ESAuthorizationPetitionEvent)
public class ESAuthorizationPetitionEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case instigator
        case petitioner
        case flags
        case flags_array
        case right_count
        case rights
        case instigator_token
        case petitioner_token
    }
    
    
    public var flags_array: [String] {
        get {
            guard let data = flagsData else { return [] }
            return (try? JSONDecoder().decode([String].self, from: data)) ?? []
        }
        set {
            flagsData = try? JSONEncoder().encode(newValue)
        }
    }
    
    public var rights: [String] {
        get {
            guard let data = rightsData else { return [] }
            return (try? JSONDecoder().decode([String].self, from: data)) ?? []
        }
        set {
            rightsData = try? JSONEncoder().encode(newValue)
        }
    }
    
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: AuthorizationPetitionEvent = message.event.authorization_petition!
        let description = NSEntityDescription.entity(forEntityName: "ESAuthorizationPetitionEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        /// Each process and token on its own: Endpoint Security can leave out a process (`NULL`) and still give its
        /// token, and before message version 8 gives the processes without tokens.
        let process = { (process: Process) in
            ESProcess(from: process, version: message.version, insertIntoManagedObjectContext: context)
        }
        let token = { (token: AuditToken) in ESAuditToken(from: token, insertIntoManagedObjectContext: context) }
        self.instigator = event.instigator.map(process)
        self.instigator_token = event.instigator_token.map(token)
        self.petitioner = event.petitioner.map(process)
        self.petitioner_token = event.petitioner_token.map(token)
        
        self.flags = event.flags
        self.flags_array = event.flags_array
        self.right_count = event.right_count
        self.rights = event.rights
    }
}

extension ESAuthorizationPetitionEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(instigator, forKey: .instigator)
        try container.encode(petitioner, forKey: .petitioner)
        try container.encode(flags_array, forKey: .flags_array)
        try container.encode(flags, forKey: .flags)
        try container.encode(right_count, forKey: .right_count)
        try container.encode(rights, forKey: .rights)
        try container.encode(instigator_token, forKey: .instigator_token)
        try container.encode(petitioner_token, forKey: .petitioner_token)
    }
}
