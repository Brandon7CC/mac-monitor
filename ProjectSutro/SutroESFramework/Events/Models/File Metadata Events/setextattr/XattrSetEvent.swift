//
//  XattrSetEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_setextattr_t
public struct XattrSetEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var target: File
    public var extattr: String
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: XattrSetEvent, rhs: XattrSetEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the extended attribute (xattr) set event
        let event: es_event_setextattr_t = rawMessage.pointee.event.setextattr
        
        target = File(from: event.target.pointee)
        extattr = event.extattr.string ?? ""
    }
}
