//
//  GetTaskEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//

import Foundation
import EndpointSecurity



// MARK: - Get Task Event https://developer.apple.com/documentation/endpointsecurity/es_event_get_task_t
public struct GetTaskEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    public var target: Process
    
    /* field available only if message version >= 5 */
    public var type: Int16
    public var type_string = ""
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event: es_event_get_task_t = rawMessage.pointee.event.get_task
        let version: Int = Int(rawMessage.pointee.version)
        
        target = Process(from: event.target.pointee, version: version)
        type = Int16(event.type.rawValue)
        
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension GetTaskEvent: ESEnrichable {
    /// `es_get_task_type_t`: the call that asked for the task port.
    private static let typeNames = ConstantNames([
        ES_GET_TASK_TYPE_EXPOSE_TASK.rawValue: "ES_GET_TASK_TYPE_EXPOSE_TASK",
        ES_GET_TASK_TYPE_IDENTITY_TOKEN.rawValue: "ES_GET_TASK_TYPE_IDENTITY_TOKEN",
        ES_GET_TASK_TYPE_TASK_FOR_PID.rawValue: "ES_GET_TASK_TYPE_TASK_FOR_PID",
    ])
    
    /// Derive the task port type's name.
    public mutating func enrich() {
        type_string = Self.typeNames.name(of: Int(type))
    }
}
