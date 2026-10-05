//
//  FileWriteEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/1/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_write_t
public struct FileWriteEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var target: File
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: FileWriteEvent, rhs: FileWriteEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the file write event
        let event: es_event_write_t = rawMessage.pointee.event.write
        target = File(from: event.target.pointee)
    }
}
