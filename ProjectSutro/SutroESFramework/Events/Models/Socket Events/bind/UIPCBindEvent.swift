//
//  UIPCBindEvent.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 10/1/25.
//


// https://developer.apple.com/documentation/endpointsecurity/es_event_uipc_connect_t
public struct UIPCBindEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var dir: File
    public var filename: String
    public var mode: Int32
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: UIPCBindEvent, rhs: UIPCBindEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_uipc_bind_t = rawMessage.pointee.event.uipc_bind
        
        dir = File(from: event.dir.pointee)
        filename = event.filename.string ?? ""
        mode = Int32(event.mode)
    }
}
