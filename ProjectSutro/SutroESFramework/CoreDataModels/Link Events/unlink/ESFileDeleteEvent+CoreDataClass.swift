//
//  ESFileDeleteEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/1/23.
//
//

import Foundation
import CoreData

@objc(ESFileDeleteEvent)
public class ESFileDeleteEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESFile
    @NSManaged public var parent_dir: ESFile

    enum CodingKeys: CodingKey {
        case target
        case parent_dir
    }
    
    // MARK: - Custom Core Data initilizer for ESFileDeleteEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: FileDeleteEvent = message.event.unlink!
        let description = NSEntityDescription.entity(forEntityName: "ESFileDeleteEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESFileDeleteEvent.target))
        attach(ESFile.row(for: event.parent_dir, in: context), to: #keyPath(ESFileDeleteEvent.parent_dir))
    }
}

// MARK: - Encodable conformance
extension ESFileDeleteEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(parent_dir, forKey: .parent_dir)
    }
}
