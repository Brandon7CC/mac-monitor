//
//  UIPCBindEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/25.
//


// https://developer.apple.com/documentation/endpointsecurity/es_event_uipc_connect_t
public struct UIPCBindEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var dir: File
    public var filename: String
    public var mode: Int32
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_uipc_bind_t = rawMessage.pointee.event.uipc_bind
        
        dir = File(from: event.dir.pointee)
        filename = event.filename.string ?? ""
        mode = Int32(event.mode)
    }
}
