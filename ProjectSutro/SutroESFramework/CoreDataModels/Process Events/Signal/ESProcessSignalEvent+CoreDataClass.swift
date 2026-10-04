//
//  ESProcessSignalEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//
//

import Foundation
import CoreData

@objc(ESProcessSignalEvent)
public class ESProcessSignalEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case sig
        case signal_name
        case target
        case instigator
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessSignalEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let signalEvent: ProcessSignalEvent = message.event.signal!
        let description = NSEntityDescription.entity(forEntityName: "ESProcessSignalEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = signalEvent.id
        self.sig = Int32(truncatingIfNeeded: signalEvent.sig)
        self.signal_name = signalEvent.signal_name
        
        /// Process structures
        self.target = ESProcess(from: signalEvent.target, version: message.version, insertIntoManagedObjectContext: context)
        if let instigator = signalEvent.instigator {
            self.instigator = ESProcess(from: instigator, version: message.version, insertIntoManagedObjectContext: context)
        }
    }
}

// MARK: - Encodable conformance
extension ESProcessSignalEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(sig, forKey: .sig)
        try container.encode(signal_name, forKey: .signal_name)
        
        try container.encode(target, forKey: .target)
        try container.encode(instigator, forKey: .instigator)
    }
}
