//
//  FileDeleteEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/1/23.
//

import Foundation


/// Models an `es_event_unlink_t` event: https://developer.apple.com/documentation/endpointsecurity/es_event_unlink_t
public struct FileDeleteEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var target, parent_dir: File
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: FileDeleteEvent, rhs: FileDeleteEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_unlink_t = rawMessage.pointee.event.unlink
        
        target = File(from: event.target.pointee)
        parent_dir = File(from: event.parent_dir.pointee)
    }
}
