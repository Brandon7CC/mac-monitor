//
//  ESFileCloseEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//
//

import Foundation
import CoreData

@objc(ESFileCloseEvent)
public class ESFileCloseEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case target
        case modified
        case was_mapped_writable
    }
    
    // MARK: - Custom Core Data initilizer for ESFileCloseEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: FileCloseEvent = message.event.close!
        let description = NSEntityDescription.entity(forEntityName: "ESFileCloseEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESFileCloseEvent.target))
        self.modified = event.modified
        self.was_mapped_writable = event.was_mapped_writable ?? false
    }
}

// MARK: - Encodable conformance
extension ESFileCloseEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(modified, forKey: .modified)
        try container
            .encodeIfPresent(was_mapped_writable, forKey: .was_mapped_writable)
    }
}
