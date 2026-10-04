//
//  UIPCConnectEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/25.
//

// https://developer.apple.com/documentation/endpointsecurity/es_event_uipc_connect_t
public struct UIPCConnectEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var file: File
    public var domain, type, `protocol`: Int32
    
    public var type_string = "", domain_string = "", protocol_string = ""
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: UIPCConnectEvent, rhs: UIPCConnectEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_uipc_connect_t = rawMessage.pointee.event.uipc_connect
        
        file = File(from: event.file.pointee)
        domain = event.domain
        `protocol` = event.protocol
        type = event.type
        
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension UIPCConnectEvent: ESEnrichable {
    /// Derive the names of the socket's domain, protocol, and type.
    public mutating func enrich() {
        domain_string = resolve(domain: domain)
        protocol_string = resolve(protocol: `protocol`)
        type_string = resolve(type: type)
    }
}
