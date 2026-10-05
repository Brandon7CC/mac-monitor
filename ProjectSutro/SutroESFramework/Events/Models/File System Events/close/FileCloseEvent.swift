//
//  FileCloseEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_close_t
public struct FileCloseEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var target: File
    public var modified: Bool
    public var was_mapped_writable: Bool?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: FileCloseEvent, rhs: FileCloseEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the file write event
        let event: es_event_close_t = rawMessage.pointee.event.close
        let version: Int = Int(rawMessage.pointee.version)
        
        target = File(from: event.target.pointee)
        modified = event.modified
        
        if version >= 6 {
            was_mapped_writable = event.was_mapped_writable
        }
    }
}
