//
//  XattrGetEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 11/17/25.
//

import Foundation

// Retrieve an extended attribute
// https://developer.apple.com/documentation/endpointsecurity/es_event_getextattr_t
public struct XattrGetEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var target: File
    public var extattr: String
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: XattrGetEvent, rhs: XattrGetEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the extended attribute (xattr) get event
        let event: es_event_getextattr_t = rawMessage.pointee.event.getextattr
        
        target = File(from: event.target.pointee)
        extattr = event.extattr.string ?? ""
    }
}
