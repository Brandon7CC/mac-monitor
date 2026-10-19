//
//  MMapEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_mmap_t
public struct MMapEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var protection, max_protection, flags: Int32
    /// Endpoint Security's `uint64_t`, kept by bit pattern as `Stat`'s `st_ino` is.
    public var file_pos: Int64
    public var source: File
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: MMapEvent, rhs: MMapEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let mmapEvent: es_event_mmap_t = rawMessage.pointee.event.mmap
        
        self.protection = mmapEvent.protection
        self.max_protection = mmapEvent.max_protection
        self.flags = mmapEvent.flags
        self.file_pos = Int64(bitPattern: mmapEvent.file_pos)
        self.source = File(from: mmapEvent.source.pointee)
    }
}
