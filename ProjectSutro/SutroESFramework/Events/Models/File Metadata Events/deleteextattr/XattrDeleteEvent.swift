//
//  XattrEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation
import EndpointSecurity


// https://developer.apple.com/documentation/endpointsecurity/es_event_deleteextattr_t
public struct XattrDeleteEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var target: File
    public var extattr: String
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the extended attribute (xattr) set event
        let event: es_event_deleteextattr_t = rawMessage.pointee.event.deleteextattr
        
        target = File(from: event.target.pointee)
        extattr = event.extattr.string ?? ""
    }
}
