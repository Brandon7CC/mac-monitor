//
//  ESProcessTraceEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//
//

import Foundation
import CoreData

@objc(ESProcessTraceEvent)
public class ESProcessTraceEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESProcess

    enum CodingKeys: CodingKey {
        case target
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessTraceEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let traceEvent: ProcessTraceEvent = message.event.trace!
        let description = NSEntityDescription.entity(forEntityName: "ESProcessTraceEvent", in: context)!
        self.init(entity: description, insertInto: context)

        self.target = ESProcess(from: traceEvent.target, version: message.version, insertIntoManagedObjectContext: context)
    }
}

// MARK: - Encodable conformance
extension ESProcessTraceEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
    }
}
