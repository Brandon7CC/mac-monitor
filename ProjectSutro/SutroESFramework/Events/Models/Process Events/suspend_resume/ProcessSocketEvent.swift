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
public struct ProcessSocketEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    
    public var target: Process?
    public var type: Int32
    public var type_string = ""
    
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the socket event "proc_suspend_resume"
        let socketEvent: es_event_proc_suspend_resume_t = rawMessage.pointee.event.proc_suspend_resume
        
        self.target = socketEvent.target.map { Process(from: $0.pointee, version: Int(rawMessage.pointee.version)) }
        
        self.type = Int32(socketEvent.type.rawValue)
        
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension ProcessSocketEvent: ESEnrichable {
    /// `es_proc_suspend_resume_type_t`: the call made on the target.
    private static let typeNames = ConstantNames([
        ES_PROC_SUSPEND_RESUME_TYPE_RESUME.rawValue: "ES_PROC_SUSPEND_RESUME_TYPE_RESUME",
        ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND.rawValue: "ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND",
        ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS.rawValue: "ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS",
    ])
    
    /// Derive the type's name.
    public mutating func enrich() {
        type_string = Self.typeNames.name(of: Int(type))
    }
}
