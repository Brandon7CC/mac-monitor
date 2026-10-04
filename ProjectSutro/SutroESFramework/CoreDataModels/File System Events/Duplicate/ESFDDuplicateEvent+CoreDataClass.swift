//
//  ESFDDuplicateEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 2/16/23.
//
//

import Foundation
import CoreData

@objc(ESFDDuplicateEvent)
public class ESFDDuplicateEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESFDDuplicateEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: FDDuplicateEvent = message.event.dup!
        let description = NSEntityDescription.entity(forEntityName: "ESFDDuplicateEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESFDDuplicateEvent.target))
    }
}

// MARK: - Encodable conformance
extension ESFDDuplicateEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(id, forKey: .id)
        try container.encode(target, forKey: .target)
    }
}
