//
//  ESGetTaskEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//
//

import Foundation
import CoreData

@objc(ESGetTaskEvent)
public class ESGetTaskEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESProcess
    @NSManaged public var type: Int16
    @NSManaged public var type_string: String

    enum CodingKeys: CodingKey {
        case target
        case type
        case type_string
    }
    
    // MARK: - Custom Core Data initilizer for ESGetTaskEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: GetTaskEvent = message.event.get_task!
        let description = NSEntityDescription.entity(forEntityName: "ESGetTaskEvent", in: context)!
        self.init(entity: description, insertInto: context)

        self.target = ESProcess(
            from: event.target,
            version: message.version,
            insertIntoManagedObjectContext: context
        )
        self.type = event.type
        self.type_string = event.type_string
    }
}

// MARK: - Encodable conformance
extension ESGetTaskEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(target, forKey: .target)
        try container.encode(type, forKey: .type)
        try container.encode(type_string, forKey: .type_string)
    }
}

