//
//  PTYGrantEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/29/25.
//

import Foundation

// https://developer.apple.com/documentation/endpointsecurity/es_event_pty_grant_t
public struct PTYGrantEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    /// `dev_t`
    public var dev: Int64
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: PTYGrantEvent, rhs: PTYGrantEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_pty_grant_t = rawMessage.pointee.event.pty_grant
        
        dev = Int64(event.dev)
    }
}
