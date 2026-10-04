//
//  ESSetModeEvent+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/29/25.
//
//

import Foundation
import CoreData


@objc(ESSetModeEvent)
public class ESSetModeEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case mode
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESSetModeEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: SetModeEvent = message.event.setmode!
        let description = NSEntityDescription.entity(forEntityName: "ESSetModeEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        self.mode = event.mode
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESSetModeEvent.target))
    }
}

// MARK: - Encodable conformance
extension ESSetModeEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(mode, forKey: .mode)
        try container.encode(target, forKey: .target)
    }
}
