//
//  LWLoginEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/18/23.
//

import Foundation
import EndpointSecurity
import OSLog


// https://developer.apple.com/documentation/endpointsecurity/es_event_lw_session_login_t
public struct LWLoginEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var username: String
    public var graphical_session_id: Int32
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(username)
        hasher.combine(id)
    }
    
    public static func == (lhs: LWLoginEvent, rhs: LWLoginEvent) -> Bool {
        if lhs.graphical_session_id == rhs.graphical_session_id && lhs.id == rhs.id && lhs.username == rhs.username {
            return true
        }
        
        return false
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let lwLoginEvent: es_event_lw_session_login_t = rawMessage.pointee.event.lw_session_login.pointee
        
        self.username = lwLoginEvent.username.string ?? ""
        /// A `uint32_t`, kept by bit pattern: one of 2^31 or more has no `Int32`.
        self.graphical_session_id = Int32(bitPattern: lwLoginEvent.graphical_session_id)
    }
}
