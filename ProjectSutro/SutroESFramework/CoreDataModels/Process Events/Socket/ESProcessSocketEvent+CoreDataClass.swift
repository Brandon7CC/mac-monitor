//
//  ESProcessSocketEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//
//

import Foundation
import CoreData

@objc(ESProcessSocketEvent)
public class ESProcessSocketEvent: NSManagedObject, Identifiable {
    @NSManaged public var type: Int32
    @NSManaged public var type_string: String
    @NSManaged public var target: ESProcess?

    enum CodingKeys: CodingKey {
        case type
        case type_string
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessSocketEvent
    convenience init(from event: ProcessSocketEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.type_string = event.type_string
        self.type = event.type
        
        self.target = ESProcess.insert(event.target, version: message.version, in: context)
    }
}

// MARK: - Encodable conformance
extension ESProcessSocketEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(type_string, forKey: .type_string)
        try container.encode(target, forKey: .target)
    }
}
