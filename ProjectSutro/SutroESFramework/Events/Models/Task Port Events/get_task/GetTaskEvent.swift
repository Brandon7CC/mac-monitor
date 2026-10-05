//
//  GetTaskEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//

import Foundation
import EndpointSecurity



// MARK: - Get Task Event https://developer.apple.com/documentation/endpointsecurity/es_event_get_task_t
public struct GetTaskEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    public var target: Process
    
    /* field available only if message version >= 5 */
    public var type: Int16
    public var type_string = ""
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: GetTaskEvent, rhs: GetTaskEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
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
    /// Derive the task port type's name.
    public mutating func enrich() {
        switch es_get_task_type_t(rawValue: UInt32(truncatingIfNeeded: type)) {
        case ES_GET_TASK_TYPE_EXPOSE_TASK:
            type_string = "ES_GET_TASK_TYPE_EXPOSE_TASK"
        case ES_GET_TASK_TYPE_IDENTITY_TOKEN:
            type_string = "ES_GET_TASK_TYPE_IDENTITY_TOKEN"
        case ES_GET_TASK_TYPE_TASK_FOR_PID:
            type_string = "ES_GET_TASK_TYPE_TASK_FOR_PID"
        default:
            type_string = "UNKNOWN"
        }
    }
}
