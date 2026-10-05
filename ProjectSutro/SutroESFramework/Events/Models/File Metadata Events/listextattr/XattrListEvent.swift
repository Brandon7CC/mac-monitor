//
//  XattrListEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/19/25.
//

import Foundation


// List extended attributes of a file
// https://developer.apple.com/documentation/endpointsecurity/es_event_listextattr_t
public struct XattrListEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var target: File
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: XattrListEvent, rhs: XattrListEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the extended attribute (list) get event
        let event: es_event_listextattr_t = rawMessage.pointee.event.listextattr
        
        target = File(from: event.target.pointee)
    }
}
