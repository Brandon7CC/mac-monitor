//
//  OpenSSHLogoutEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation


// MARK: - OpenSSH Logout event model: https://developer.apple.com/documentation/endpointsecurity/3228936-es_events_t/3930482-openssh_logout
public struct SSHLogoutEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var source_address_type: Int32
    public var source_address_type_string = ""
    
    public var source_address: String
    public var username: String
    
    public var uid: Int32
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: SSHLogoutEvent, rhs: SSHLogoutEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_openssh_logout_t = rawMessage.pointee.event.openssh_logout.pointee
        
        username = event.username.toString() ?? ""
        source_address = event.source_address.toString() ?? ""
        uid = Int32(event.uid)
        
        source_address_type = Int32(event.source_address_type.rawValue)
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension SSHLogoutEvent: ESEnrichable {
    /// Derive the source address type's name.
    public mutating func enrich() {
        switch es_address_type_t(rawValue: UInt32(truncatingIfNeeded: source_address_type)) {
        case ES_ADDRESS_TYPE_NONE:
            source_address_type_string = "ES_ADDRESS_TYPE_NONE"
            break
        case ES_ADDRESS_TYPE_IPV4:
            source_address_type_string = "ES_ADDRESS_TYPE_IPV4"
            break
        case ES_ADDRESS_TYPE_IPV6:
            source_address_type_string = "ES_ADDRESS_TYPE_IPV6"
            break
        case ES_ADDRESS_TYPE_NAMED_SOCKET:
            source_address_type_string = "ES_ADDRESS_TYPE_NAMED_SOCKET"
            break
        default:
            source_address_type_string = "Unknown"
            break
        }
    }
}
