//
//  CodeSignatureInvalidatedEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//

import Foundation
import EndpointSecurity


// https://developer.apple.com/documentation/endpointsecurity/es_event_cs_invalidated_t
public struct CodeSignatureInvalidatedEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    init(from rawMessage: UnsafePointer<es_message_t>) {}
}
