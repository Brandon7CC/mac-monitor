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
public class ESProcessCheckEvent: NSManagedObject {
    
    enum CodingKeys: CodingKey {
        case id
        case type
        case type_string
        case flavor
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessCheckEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let procCheckEvent: ProcessCheckEvent = message.event.proc_check!
        let description = NSEntityDescription.entity(forEntityName: "ESProcessCheckEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = procCheckEvent.id
        
        self.type = procCheckEvent.type
        self.type_string = procCheckEvent.type_string
        self.flavor = Int32(procCheckEvent.flavor)
        
        if let target = procCheckEvent.target {
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
