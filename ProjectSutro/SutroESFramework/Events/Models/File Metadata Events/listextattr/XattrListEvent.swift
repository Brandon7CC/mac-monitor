//
//  XattrListEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/19/25.
//

import Foundation


// List extended attributes of a file
// https://developer.apple.com/documentation/endpointsecurity/es_event_listextattr_t
public struct XattrListEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var target: File
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the extended attribute (list) get event
        let event: es_event_listextattr_t = rawMessage.pointee.event.listextattr
        
        target = File(from: event.target.pointee)
    }
}
