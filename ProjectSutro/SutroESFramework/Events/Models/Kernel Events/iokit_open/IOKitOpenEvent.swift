//
//  IOKitOpenEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation
import EndpointSecurity


// https://developer.apple.com/documentation/endpointsecurity/es_event_iokit_open_t
public struct IOKitOpenEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var user_client_type: Int64
    public var user_client_class: String
    
    /* fields available only if message version >= 10 */
    /// A `uint64_t`, kept by bit pattern. `nil` before message version 10, or in a record from Mac Monitor before
    /// 3.0.0, which left it out when the parent path was empty.
    public var parent_registry_id: Int64?
    public var parent_path: String?
    
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let ioKitEvent: es_event_iokit_open_t = rawMessage.pointee.event.iokit_open
        let version: Int = Int(rawMessage.pointee.version)
        
        self.user_client_class = ioKitEvent.user_client_class.string ?? ""
        self.user_client_type = Int64(ioKitEvent.user_client_type)
        /// A `uint64_t`, kept by bit pattern: one of 2^63 or more has no `Int64`.
        parent_registry_id = version >= 10 ? Int64(bitPattern: ioKitEvent.parent_registry_id) : nil
        parent_path = version >= 10 ? ioKitEvent.parent_path.string : nil
    }
}
