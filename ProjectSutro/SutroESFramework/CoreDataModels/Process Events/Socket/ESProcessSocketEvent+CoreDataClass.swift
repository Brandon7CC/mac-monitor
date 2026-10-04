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
public class ESProcessSocketEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case type
        case type_string
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessSocketEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let processSocketEvent: ProcessSocketEvent = message.event.proc_suspend_resume!
        let description = NSEntityDescription.entity(forEntityName: "ESProcessSocketEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.id = processSocketEvent.id
        self.type_string = processSocketEvent.type_string
        self.type = processSocketEvent.type
        
        if let target = processSocketEvent.target {
            self.target = ESProcess(from: target, version: message.version, insertIntoManagedObjectContext: context)
        }
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
