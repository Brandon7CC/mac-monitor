//
//  SetModeEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/29/25.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_setmode_t
public struct SetModeEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var mode: Int32
    public var target: File
    
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: SetModeEvent, rhs: SetModeEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_setmode_t = rawMessage.pointee.event.setmode
        
        mode = Int32(event.mode)
        target = File(from: event.target.pointee)
    }
}
