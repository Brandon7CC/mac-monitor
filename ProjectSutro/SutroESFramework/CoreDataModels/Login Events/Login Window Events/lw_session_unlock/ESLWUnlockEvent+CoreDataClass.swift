//
//  ESLWUnlockEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/18/23.
//
//

import Foundation
import CoreData

@objc(ESLWUnlockEvent)
public class ESLWUnlockEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, username, graphical_session_id
    }
    
    // MARK: - Custom Core Data initilizer for ESLWUnlockEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let lwUnlockEvent: LWUnlockEvent = message.event.lw_session_unlock!
        let description = NSEntityDescription.entity(forEntityName: "ESLWUnlockEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.id = lwUnlockEvent.id
        self.username = lwUnlockEvent.username
        self.graphical_session_id = lwUnlockEvent.graphical_session_id
    }
    
}

// MARK: - Encodable conformance
extension ESLWUnlockEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
//        try container.encode(id, forKey: .id)
        try container.encode(username, forKey: .username)
        /// A `uint32_t`, kept by bit pattern: written unsigned, as eslogger writes it.
        try container.encode(UInt32(bitPattern: graphical_session_id), forKey: .graphical_session_id)
    }
}
