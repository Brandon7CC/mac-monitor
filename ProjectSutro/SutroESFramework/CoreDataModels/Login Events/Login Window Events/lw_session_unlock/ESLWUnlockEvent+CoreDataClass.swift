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
public class ESLWUnlockEvent: NSManagedObject, Identifiable {
    @NSManaged public var username: String?
    @NSManaged public var graphical_session_id: Int32

    enum CodingKeys: CodingKey {
        case username, graphical_session_id
    }
    
    // MARK: - Custom Core Data initilizer for ESLWUnlockEvent
    convenience init(from event: LWSessionEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.username = event.username
        self.graphical_session_id = event.graphical_session_id
    }
    
}

// MARK: - Encodable conformance
extension ESLWUnlockEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(username, forKey: .username)
        /// A `uint32_t`, kept by bit pattern: written unsigned, as eslogger writes it.
        try container.encode(UInt32(bitPattern: graphical_session_id), forKey: .graphical_session_id)
    }
}
