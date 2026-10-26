//
//  LWUnlockEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/18/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_lw_session_unlock_t
public struct LWUnlockEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var username: String
    public var graphical_session_id: Int32
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let lwUnlockEvent: es_event_lw_session_unlock_t = rawMessage.pointee.event.lw_session_unlock.pointee
        
        self.username = lwUnlockEvent.username.string ?? ""
        /// A `uint32_t`, kept by bit pattern: one of 2^31 or more has no `Int32`.
        self.graphical_session_id = Int32(bitPattern: lwUnlockEvent.graphical_session_id)
    }
}
