//
//  ESProcessCheckEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//
//

import Foundation
import CoreData

@objc(ESProcessCheckEvent)
public class ESProcessCheckEvent: NSManagedObject, Identifiable {
    @NSManaged public var flavor: Int32
    @NSManaged public var type: Int32
    @NSManaged public var type_string: String
    @NSManaged public var target: ESProcess?

    enum CodingKeys: CodingKey {
        case type
        case type_string
        case flavor
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessCheckEvent
    convenience init(from event: ProcessCheckEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.type = event.type
        self.type_string = event.type_string
        self.flavor = Int32(truncatingIfNeeded: event.flavor)
        
        if let target = event.target {
            self.target = ESProcess(from: target, version: message.version, insertIntoManagedObjectContext: context)
        }
    }
}

// MARK: - Encodable conformance
extension ESProcessCheckEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(type, forKey: .type)
        try container.encode(type_string, forKey: .type_string)
        try container.encode(flavor, forKey: .flavor)
        
        try container.encode(target, forKey: .target)
    }
}
