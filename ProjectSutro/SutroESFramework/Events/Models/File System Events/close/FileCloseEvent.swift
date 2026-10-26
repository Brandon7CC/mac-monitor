//
//  FileCloseEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_close_t
public struct FileCloseEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var target: File
    public var modified: Bool
    public var was_mapped_writable: Bool?
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the file write event
        let event: es_event_close_t = rawMessage.pointee.event.close
        let version: Int = Int(rawMessage.pointee.version)
        
        target = File(from: event.target.pointee)
        modified = event.modified
        was_mapped_writable = version >= 6 ? event.was_mapped_writable : nil
    }
}
