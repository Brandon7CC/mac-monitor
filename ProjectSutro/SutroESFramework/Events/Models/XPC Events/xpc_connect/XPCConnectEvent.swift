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


public struct XPCConnectEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    public var service_name: String
    public var service_domain_type: Int32
    public var service_domain_type_string = ""
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let xpcConnectEvent: es_event_xpc_connect_t = rawMessage.pointee.event.xpc_connect.pointee
        
        self.service_name = xpcConnectEvent.service_name.string ?? ""
        
        self.service_domain_type = Int32(xpcConnectEvent.service_domain_type.rawValue)
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension XPCConnectEvent: ESEnrichable {
    /// `es_xpc_domain_type_t`: the type of the service's domain.
    private static let domainTypeNames = ConstantNames([
        ES_XPC_DOMAIN_TYPE_GUI.rawValue: "GUI",
        ES_XPC_DOMAIN_TYPE_PID.rawValue: "PID",
        ES_XPC_DOMAIN_TYPE_PORT.rawValue: "PORT",
        ES_XPC_DOMAIN_TYPE_USER.rawValue: "USER",
        ES_XPC_DOMAIN_TYPE_SYSTEM.rawValue: "SYSTEM",
        ES_XPC_DOMAIN_TYPE_MANAGER.rawValue: "MANAGER",
        ES_XPC_DOMAIN_TYPE_SESSION.rawValue: "SESSION",
        ES_XPC_DOMAIN_TYPE_USER_LOGIN.rawValue: "USER LOGIN",
    ])
    
    /// Derive the service domain type's name.
    public mutating func enrich() {
        service_domain_type_string = Self.domainTypeNames.name(of: Int(service_domain_type))
    }
}
