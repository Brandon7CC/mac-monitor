//
//  FileDeleteEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/1/23.
//

import Foundation


/// Models an `es_event_unlink_t` event: https://developer.apple.com/documentation/endpointsecurity/es_event_unlink_t
public struct FileDeleteEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var target, parent_dir: File
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_unlink_t = rawMessage.pointee.event.unlink
        
        target = File(from: event.target.pointee)
        parent_dir = File(from: event.parent_dir.pointee)
    }
}
