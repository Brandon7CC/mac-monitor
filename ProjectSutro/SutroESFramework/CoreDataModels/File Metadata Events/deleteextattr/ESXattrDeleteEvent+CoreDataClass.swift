//
//  ESXattrDeleteEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData

@objc(ESXattrDeleteEvent)
public class ESXattrDeleteEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESFile
    @NSManaged public var extattr: String

    enum CodingKeys: CodingKey {
        case target, extattr
    }
    
    // MARK: - Custom Core Data initilizer for ESXattrDeleteEvent
    convenience init(from event: XattrDeleteEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESXattrDeleteEvent.target))
        extattr = event.extattr
    }
}

// MARK: - Encodable conformance
extension ESXattrDeleteEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(extattr, forKey: .extattr)
    }
}
