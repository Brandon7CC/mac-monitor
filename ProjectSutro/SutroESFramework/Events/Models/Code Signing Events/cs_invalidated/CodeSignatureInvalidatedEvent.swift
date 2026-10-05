//
//  CodeSignatureInvalidatedEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//

import Foundation
import EndpointSecurity


// https://developer.apple.com/documentation/endpointsecurity/es_event_cs_invalidated_t
public struct CodeSignatureInvalidatedEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: CodeSignatureInvalidatedEvent, rhs: CodeSignatureInvalidatedEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the cs invalidated event
        _ = rawMessage.pointee.event.cs_invalidated
    }
}
