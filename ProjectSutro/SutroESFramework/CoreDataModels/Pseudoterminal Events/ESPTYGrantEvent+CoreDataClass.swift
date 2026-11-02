//
//  ESPTYGrantEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 9/29/25.
//
//

import Foundation
import CoreData


@objc(ESPTYGrantEvent)
public class ESPTYGrantEvent: NSManagedObject, Identifiable {
    @NSManaged public var dev: Int64

    enum CodingKeys: CodingKey {
        case dev
    }
    
    // MARK: - Custom Core Data initilizer for ESPTYGrantEvent
    convenience init(from event: PTYGrantEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        self.dev = event.dev
    }
}

// MARK: - Encodable conformance
extension ESPTYGrantEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(dev, forKey: .dev)
    }
}
