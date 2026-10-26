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
public class ESFileCloseEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESFile
    @NSManaged public var modified: Bool
    
    // message >= 6
    @NSManaged public var was_mapped_writable: Bool

    enum CodingKeys: CodingKey {
        case target
        case modified
        case was_mapped_writable
    }
    
    // MARK: - Custom Core Data initilizer for ESFileCloseEvent
    convenience init(from event: FileCloseEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
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
