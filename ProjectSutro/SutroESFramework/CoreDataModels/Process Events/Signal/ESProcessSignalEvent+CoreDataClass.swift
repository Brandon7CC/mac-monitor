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
public class ESProcessSignalEvent: NSManagedObject, Identifiable {
    @NSManaged public var sig: Int32
    @NSManaged public var signal_name: String
    @NSManaged public var target: ESProcess
    @NSManaged public var instigator: ESProcess?

    enum CodingKeys: CodingKey {
        case sig
        case signal_name
        case target
        case instigator
    }
    
    // MARK: - Custom Core Data initilizer for ESProcessSignalEvent
    convenience init(from event: ProcessSignalEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        self.sig = Int32(truncatingIfNeeded: event.sig)
        self.signal_name = event.signal_name
        
        /// Process structures
        self.target = ESProcess(from: event.target, version: message.version, insertIntoManagedObjectContext: context)
        if let instigator = event.instigator {
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
