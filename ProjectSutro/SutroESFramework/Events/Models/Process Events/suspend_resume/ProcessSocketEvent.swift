//
//  ProcessSocketEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//

import Foundation


/**
 * @brief Fired when one of pid_suspend, pid_resume or pid_shutdown_sockets
 * is called on a process.
 *
 * @field target The process that is being suspended, resumed, or is the object
 * of a pid_shutdown_sockets call.
 * @field type The type of operation that was called on the target process.
 *
 * @note This event type does not support caching.
 */
/// We call [es_event_proc_suspend_resume_t](https://developer.apple.com/documentation/endpointsecurity/es_event_proc_suspend_resume_t)
///  a `ProcessSocketEvent`
public struct ProcessSocketEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var target: Process?
    public var type: Int32
    public var type_string = ""
    
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: ProcessSocketEvent, rhs: ProcessSocketEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the socket event "proc_suspend_resume"
        let socketEvent: es_event_proc_suspend_resume_t = rawMessage.pointee.event.proc_suspend_resume
        
        if let target = socketEvent.target {
            self.target = Process(from: target.pointee, version: Int(rawMessage.pointee.version))
        }
        
        self.type = Int32(socketEvent.type.rawValue)
        
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension ProcessSocketEvent: ESEnrichable {
    /// Derive the type's name.
    public mutating func enrich() {
        switch es_proc_suspend_resume_type_t(rawValue: UInt32(truncatingIfNeeded: type)) {
        case ES_PROC_SUSPEND_RESUME_TYPE_RESUME:
            self.type_string = "ES_PROC_SUSPEND_RESUME_TYPE_RESUME"
        case ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND:
            self.type_string = "ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND"
        case ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS:
            self.type_string = "ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS"
        default:
            self.type_string = "UNKNOWN"
        }
    }
}
