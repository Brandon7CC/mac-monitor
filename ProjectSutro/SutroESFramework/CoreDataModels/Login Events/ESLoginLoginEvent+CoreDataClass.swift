//
//  ESLoginLoginEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/17/23.
//
//

import Foundation
import CoreData

@objc(ESLoginLoginEvent)
public class ESLoginLoginEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case success
        case failure_message
        case username
        case uid
        case uid_human
        case has_uid
    }
    
    // MARK: - Custom Core Data initilizer for ESLoginLoginEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: LoginLoginEvent = message.event.login_login!
        let description = NSEntityDescription.entity(forEntityName: "ESLoginLoginEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.id = event.id
        self.success = event.succcess
        self.failure_message = event.failure_message
        self.username = event.username
        self.has_uid = event.has_uid
        if event.has_uid {
            self.uid = event.uid as NSNumber
        }
        self.uid_human = event.uid_human
    }
}

// MARK: - Encodable conformance
extension ESLoginLoginEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(success, forKey: .success)
        try container.encode(failure_message, forKey: .failure_message)
        try container.encode(username, forKey: .username)
        try container.encode(has_uid, forKey: .has_uid)
        try container.encode(uid?.int64Value, forKey: .uid)
        try container.encodeIfPresent(uid_human, forKey: .uid_human)
    }
}
