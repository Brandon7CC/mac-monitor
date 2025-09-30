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
    public var service_name: String?
    public var service_domain_type: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(service_name)
    }
    
    public static func == (lhs: XPCConnectEvent, rhs: XPCConnectEvent) -> Bool {
        if lhs.id == rhs.id && lhs.service_name == rhs.service_name {
            return true
        }
        
        return false
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let xpcConnectEvent: es_event_xpc_connect_t = rawMessage.pointee.event.xpc_connect.pointee
        
        self.service_name = ""
        if xpcConnectEvent.service_name.length > 0 {
            self.service_name = String(cString: xpcConnectEvent.service_name.data)
        }
        
        switch(xpcConnectEvent.service_domain_type){
        case ES_XPC_DOMAIN_TYPE_GUI:
            self.service_domain_type = "GUI"
            break
        case ES_XPC_DOMAIN_TYPE_PID:
            self.service_domain_type = "PID"
            break
        case ES_XPC_DOMAIN_TYPE_PORT:
            self.service_domain_type = "PORT"
            break
        case ES_XPC_DOMAIN_TYPE_USER:
            self.service_domain_type = "USER"
            break
        case ES_XPC_DOMAIN_TYPE_SYSTEM:
            self.service_domain_type = "SYSTEM"
            break
        case ES_XPC_DOMAIN_TYPE_MANAGER:
            self.service_domain_type = "MANAGER"
            break
        case ES_XPC_DOMAIN_TYPE_SESSION:
            self.service_domain_type = "SESSION"
            break
        case ES_XPC_DOMAIN_TYPE_USER_LOGIN:
            self.service_domain_type = "USER LOGIN"
            break
        default:
            self.service_domain_type = "UNKNOWN"
        }
    }
}
