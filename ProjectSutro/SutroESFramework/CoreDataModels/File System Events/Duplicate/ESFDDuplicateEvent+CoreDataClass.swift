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
public class ESFDDuplicateEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESFile

    enum CodingKeys: CodingKey {
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESFDDuplicateEvent
    convenience init(from event: TargetFileEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESFDDuplicateEvent.target))
    }
}

// MARK: - Encodable conformance
extension ESFDDuplicateEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
    }
}
