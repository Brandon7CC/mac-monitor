//
//  ESMountEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/17/23.
//
//

import Foundation
import CoreData

@objc(ESMountEvent)
public class ESMountEvent: NSManagedObject, Identifiable {
    @NSManaged public var statfsData: Data
    @NSManaged public var disposition: Int16
    @NSManaged public var disposition_string: String

    enum CodingKeys: CodingKey {
        case statfs
        case disposition
        case disposition_string
    }
    
    public var statfs: StatFS {
        get {
            let data = statfsData
            return try! JSONDecoder().decode(StatFS.self, from: data)
        }
        set {
            statfsData = try! JSONEncoder().encode(newValue)
        }
    }
    
    // MARK: - Custom Core Data initilizer for ESMountEvent
    convenience init(from event: MountEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.statfs = event.statfs
        self.disposition = event.disposition
        self.disposition_string = event.disposition_string
    }
}

// MARK: - Encodable conformance
extension ESMountEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(statfs, forKey: .statfs)
        try container.encode(disposition, forKey: .disposition)
        try container.encode(disposition_string, forKey: .disposition_string)
    }
}
