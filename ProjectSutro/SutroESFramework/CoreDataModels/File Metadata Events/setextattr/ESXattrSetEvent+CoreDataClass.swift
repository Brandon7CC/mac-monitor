//
//  ESXattrSetEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//
//

import Foundation
import CoreData

@objc(ESXattrSetEvent)
public class ESXattrSetEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESFile
    @NSManaged public var extattr: String

    enum CodingKeys: CodingKey {
        case target, extattr
    }
    
    
    // MARK: - Custom Core Data initilizer for ESXattrSetEvent
    convenience init(from event: XattrEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESXattrSetEvent.target))
        extattr = event.extattr
    }
}

// MARK: - Encodable conformance
extension ESXattrSetEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(extattr, forKey: .extattr)
    }
}
