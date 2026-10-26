//
//  ESXattrGetEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/25.
//
//

import Foundation
import CoreData

@objc(ESXattrGetEvent)
public class ESXattrGetEvent: NSManagedObject, Identifiable {
    @NSManaged public var extattr: String
    @NSManaged public var target: ESFile

    enum CodingKeys: CodingKey {
        case target, extattr
    }
    
    
    // MARK: - Custom Core Data initilizer for ESXattrGetEvent
    convenience init(from event: XattrGetEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESXattrGetEvent.target))
        extattr = event.extattr
    }
}

// MARK: - Encodable conformance
extension ESXattrGetEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(extattr, forKey: .extattr)
    }
}
