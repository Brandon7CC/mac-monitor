//
//  XPCConnectEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/23/23.
//
// MARK: ES documentation reference `es_event_xpc_connect_t`
/**
 * @brief Notification for an XPC connection being established to a named service.
 *
 * @field service_name          Service name of the named service.
 * @field service_domain_type   The type of XPC domain in which the service resides in.
 *
 * @note This event type does not support caching (notify-only).
 */
///
///```c
/// typedef struct {
///   es_string_token_t service_name;
///   es_xpc_domain_type_t service_domain_type;
/// } es_event_xpc_connect_t;
///```
///
///


import Foundation


public struct XPCConnectEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    public var service_name: String
    public var service_domain_type: Int32
    public var service_domain_type_string = ""
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: XPCConnectEvent, rhs: XPCConnectEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let xpcConnectEvent: es_event_xpc_connect_t = rawMessage.pointee.event.xpc_connect.pointee
        
        self.service_name = ""
        if xpcConnectEvent.service_name.length > 0 {
            self.service_name = String(cString: xpcConnectEvent.service_name.data)
        }
        
        self.service_domain_type = Int32(xpcConnectEvent.service_domain_type.rawValue)
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension XPCConnectEvent: ESEnrichable {
    /// Derive the service domain type's name.
    public mutating func enrich() {
        switch es_xpc_domain_type_t(rawValue: UInt32(truncatingIfNeeded: service_domain_type)) {
        case ES_XPC_DOMAIN_TYPE_GUI:
            self.service_domain_type_string = "GUI"
            break
        case ES_XPC_DOMAIN_TYPE_PID:
            self.service_domain_type_string = "PID"
            break
        case ES_XPC_DOMAIN_TYPE_PORT:
            self.service_domain_type_string = "PORT"
            break
        case ES_XPC_DOMAIN_TYPE_USER:
            self.service_domain_type_string = "USER"
            break
        case ES_XPC_DOMAIN_TYPE_SYSTEM:
            self.service_domain_type_string = "SYSTEM"
            break
        case ES_XPC_DOMAIN_TYPE_MANAGER:
            self.service_domain_type_string = "MANAGER"
            break
        case ES_XPC_DOMAIN_TYPE_SESSION:
            self.service_domain_type_string = "SESSION"
            break
        case ES_XPC_DOMAIN_TYPE_USER_LOGIN:
            self.service_domain_type_string = "USER LOGIN"
            break
        default:
            self.service_domain_type_string = "UNKNOWN"
        }
    }
}
