//
//  MProtectEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/14/25.
//

import Foundation


/// @brief Control protection of pages
/// A type for an event that indicates a change to protection of memory-mapped pages.
/// https://developer.apple.com/documentation/endpointsecurity/es_event_mprotect_t
public struct MProtectEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var protection: Int32
    public var address, size: Int64
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: MProtectEvent, rhs: MProtectEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_mprotect_t = rawMessage.pointee.event.mprotect
        
        self.protection = event.protection
        self.address = Int64(event.address)
        self.size = Int64(event.size)
    }
}
