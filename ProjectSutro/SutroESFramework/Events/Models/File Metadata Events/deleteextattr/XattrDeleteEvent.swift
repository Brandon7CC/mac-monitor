//
//  XattrEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation
import EndpointSecurity


// https://developer.apple.com/documentation/endpointsecurity/es_event_deleteextattr_t
public struct XattrDeleteEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var target: File
    public var extattr: String
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: XattrDeleteEvent, rhs: XattrDeleteEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the extended attribute (xattr) set event
        let event: es_event_deleteextattr_t = rawMessage.pointee.event.deleteextattr
        
        target = File(from: event.target.pointee)
        extattr = event.extattr.string ?? ""
    }
}
