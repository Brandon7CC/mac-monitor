//
//  ESMProtectEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/14/25.
//
//

import Foundation
import CoreData

@objc(ESMProtectEvent)
public class ESMProtectEvent: NSManagedObject, Identifiable {
    @NSManaged public var protection: Int32
    @NSManaged public var address: Int64
    @NSManaged public var size: Int64
    
    @NSManaged public var hex_address: String
    @NSManaged public var kb_size: Int64
    @NSManaged public var flagsData: Data

    enum CodingKeys: CodingKey {
        case protection
        case address
        case size
        case hex_address
        case kb_size
        case flags
    }
    
    public var flags: [String] {
        get {
            return (try? JSONDecoder().decode([String].self, from: flagsData)) ?? []
        }
        set {
            flagsData = try! JSONEncoder().encode(newValue)
        }
    }
    
    // MARK: - Custom Core Data initilizer for ESMProtectEvent
    convenience init(from event: MProtectEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.protection = event.protection
        self.address = event.address
        self.size = event.size
        
        /// Derived again from the address: Mac Monitor up to 2.1.0 wrote a pointer in its place, and its exports and
        /// an older Security Extension's messages still carry one.
        self.hex_address = ProcessHelpers.toHex(UInt64(bitPattern: event.address))
        self.kb_size = event.kb_size
        self.flags = event.flags
    }
}

// MARK: - Encodable conformance
extension ESMProtectEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(protection, forKey: .protection)
        /// `user_addr_t` and `user_size_t`, kept by bit pattern: written unsigned, as eslogger writes them.
        try container.encode(UInt64(bitPattern: address), forKey: .address)
        try container.encode(UInt64(bitPattern: size), forKey: .size)
        
        try container.encode(hex_address, forKey: .hex_address)
        try container.encode(kb_size, forKey: .kb_size)
        try container.encode(flags, forKey: .flags)
    }
}
