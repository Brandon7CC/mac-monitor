//
//  ESFileWriteEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/1/23.
//
//

import Foundation
import CoreData


@objc(ESFileWriteEvent)
public class ESFileWriteEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESFileWriteEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: FileWriteEvent = message.event.write!
        let description = NSEntityDescription.entity(forEntityName: "ESFileWriteEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESFileWriteEvent.target))
    }
}

// MARK: - Encodable conformance
extension ESFileWriteEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
    }
}
