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
        case protection_names
        case max_protection_names
        case flag_names
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

// MARK: - Mac Monitor enrichment
/// Derived from the stored integers when read or written, not stored, as ``ESProcess/codesigningFlagNames`` is: a
/// trace exported before Mac Monitor 3.0.1, or an event from a 3.0.0 Security Extension, gets them too.
extension ESMMapEvent {
    /// The names of `protection`'s bits, such as `PROT_READ` and `PROT_EXEC`, or `PROT_NONE` for none.
    public var protectionNames: [String] {
        MemoryMappingNames.protection.names(protection)
    }
    
    /// The names of `max_protection`'s bits, in `PROT_*` names, or `PROT_NONE` for none.
    public var maxProtectionNames: [String] {
        MemoryMappingNames.protection.names(max_protection)
    }
    
    /// The names of `flags`' bits, such as `MAP_PRIVATE` and `MAP_FIXED`: none for flags of 0 (`MAP_FILE`).
    public var flagNames: [String] {
        MemoryMappingNames.flags.names(flags)
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
        /// Derived when written, from the integers: not stored.
        try container.encode(protectionNames, forKey: .protection_names)
        try container.encode(maxProtectionNames, forKey: .max_protection_names)
        try container.encode(flagNames, forKey: .flag_names)
    }
}
