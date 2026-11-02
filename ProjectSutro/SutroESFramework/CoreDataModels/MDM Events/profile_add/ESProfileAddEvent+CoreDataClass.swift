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
public class ESProfileAddEvent: NSManagedObject, Identifiable {
    @NSManaged public var instigator: ESProcess?
    @NSManaged public var is_update: Bool
    @NSManaged public var profileData: Data?
    @NSManaged public var instigator_token: ESAuditToken?

    enum CodingKeys: CodingKey {
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
    convenience init(from event: ProfileAddEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.is_update = event.is_update
        self.instigator = ESProcess.insert(event.instigator, version: message.version, in: context)
        /// On its own: Endpoint Security can leave out the instigator process (`NULL`) and still give its token
        /// (message version 8 and later).
        self.instigator_token = ESAuditToken.insert(event.instigator_token, in: context)
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
