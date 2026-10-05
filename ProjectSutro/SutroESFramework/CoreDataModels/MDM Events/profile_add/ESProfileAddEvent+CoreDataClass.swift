//
//  ESProfileAddEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/5/23.
//
//

import Foundation
import CoreData

@objc(ESProfileAddEvent)
public class ESProfileAddEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case instigator
        case is_update
        case profile
        case instigator_token
    }
    
    public var profile: Profile? {
        get {
            guard let data = profileData else { return nil }
            return (try? JSONDecoder().decode(Profile.self, from: data))
        }
        set {
            profileData = try? JSONEncoder().encode(newValue)
        }
    }
    
    // MARK: - Custom Core Data initilizer for ESProfileAddEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: ProfileAddEvent = message.event.profile_add!
        let description = NSEntityDescription.entity(forEntityName: "ESProfileAddEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.id = event.id
        self.is_update = event.is_update
        if let instigator = event.instigator {
            self.instigator = ESProcess(from: instigator, version: message.version, insertIntoManagedObjectContext: context)
        }
        /// On its own: Endpoint Security can leave out the instigator process (`NULL`) and still give its token
        /// (message version 8 and later).
        if let instigator_token = event.instigator_token {
            self.instigator_token = ESAuditToken(from: instigator_token, insertIntoManagedObjectContext: context)
        }
        self.profile = event.profile
    }
}

// MARK: - Encodable conformance
extension ESProfileAddEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(is_update, forKey: .is_update)
        
        try container.encode(instigator, forKey: .instigator)
        try container.encode(instigator_token, forKey: .instigator_token)
        try container.encodeIfPresent(profile, forKey: .profile)
    }
}
