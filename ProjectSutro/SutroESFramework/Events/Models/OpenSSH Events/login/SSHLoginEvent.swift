//
//  SSHLoginEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation
import EndpointSecurity
import OSLog


// MARK: - OpenSSH Login event model: https://developer.apple.com/documentation/endpointsecurity/3228936-es_events_t/3930481-openssh_login
public struct SSHLoginEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var success: Bool
    public var result_type: Int32
    public var result_type_string = ""
    
    public var source_address_type: Int32
    public var source_address_type_string = ""
    public var source_address: String
    
    public var username: String
    
    public var has_uid: Bool
    public var uid: Int32?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: SSHLoginEvent, rhs: SSHLoginEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_openssh_login_t = rawMessage.pointee.event.openssh_login.pointee
        
        success = event.success
        result_type = Int32(event.result_type.rawValue)
        
        
        source_address_type = Int32(event.source_address_type.rawValue)
        
        source_address = event.source_address.string ?? ""
        
        username = event.username.string ?? ""
        
        has_uid = event.has_uid
        if event.has_uid {
            /// A `uid_t`, kept by bit pattern: one of 2^31 or more has no `Int32`.
            uid = Int32(bitPattern: event.uid.uid)
        }
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension SSHLoginEvent: ESEnrichable {
    /// Derive `has_uid`, which eslogger doesn't write (there's a uid exactly when it's set), and the names of the
    /// result type and the source address type.
    public mutating func enrich() {
        has_uid = uid != nil
        switch es_openssh_login_result_type_t(rawValue: UInt32(truncatingIfNeeded: result_type)) {
        case ES_OPENSSH_AUTH_SUCCESS:
            result_type_string = "ES_OPENSSH_AUTH_SUCCESS"
            break
        case ES_OPENSSH_LOGIN_EXCEED_MAXTRIES:
            result_type_string = "ES_OPENSSH_LOGIN_EXCEED_MAXTRIES"
            break
        case ES_OPENSSH_INVALID_USER:
            result_type_string = "ES_OPENSSH_INVALID_USER"
            break
        case ES_OPENSSH_AUTH_FAIL_NONE:
            result_type_string = "ES_OPENSSH_AUTH_FAIL_NONE"
            break
        case ES_OPENSSH_AUTH_FAIL_GSSAPI:
            result_type_string = "ES_OPENSSH_AUTH_FAIL_GSSAPI"
            break
        case ES_OPENSSH_AUTH_FAIL_KBDINT:
            result_type_string = "ES_OPENSSH_AUTH_FAIL_KBDINT"
            break
        case ES_OPENSSH_AUTH_FAIL_PASSWD:
            result_type_string = "ES_OPENSSH_AUTH_FAIL_PASSWD"
            break
        case ES_OPENSSH_AUTH_FAIL_PUBKEY:
            result_type_string = "ES_OPENSSH_AUTH_FAIL_PUBKEY"
            break
        case ES_OPENSSH_LOGIN_ROOT_DENIED:
            result_type_string = "ES_OPENSSH_LOGIN_ROOT_DENIED"
            break
        case ES_OPENSSH_AUTH_FAIL_HOSTBASED:
            result_type_string = "ES_OPENSSH_AUTH_FAIL_HOSTBASED"
            break
        default:
            result_type_string = "UNKNOWN"
            break
        }
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
            source_address_type_string = "UNKNOWN"
            break
        }
    }
}
