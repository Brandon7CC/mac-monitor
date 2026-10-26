//
//  ESMMapEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData

@objc(ESMMapEvent)
public class ESMMapEvent: NSManagedObject, Identifiable {
    @NSManaged public var protection: Int32
    @NSManaged public var max_protection: Int32
    @NSManaged public var flags: Int32
    @NSManaged public var file_pos: Int64
    @NSManaged public var source: ESFile

    enum CodingKeys: CodingKey {
        case protection
        case max_protection
        case flags
        case file_pos
        case source
    }
    
    // MARK: - Custom Core Data initilizer for ESMMapEvent
    convenience init(from event: MMapEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.protection = event.protection
        self.max_protection = event.max_protection
        self.flags = event.flags
        self.file_pos = event.file_pos
        attach(ESFile.row(for: event.source, in: context), to: #keyPath(ESMMapEvent.source))
    }
}

// MARK: - Encodable conformance
extension ESMMapEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(protection, forKey: .protection)
        try container.encode(max_protection, forKey: .max_protection)
        try container.encode(flags, forKey: .flags)
        try container.encode(UInt64(bitPattern: file_pos), forKey: .file_pos)
        try container.encode(source, forKey: .source)
    }
}
