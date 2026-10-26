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
public class ESFileWriteEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESFile

    enum CodingKeys: CodingKey {
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESFileWriteEvent
    convenience init(from event: FileWriteEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
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
