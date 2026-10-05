//
//  ProcessTraceEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/3/23.
//

import Foundation


// MARK: - Process Trace Event https://developer.apple.com/documentation/endpointsecurity/es_event_trace_t
public struct ProcessTraceEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    public var target: Process
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: ProcessTraceEvent, rhs: ProcessTraceEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let traceEvent: es_event_trace_t = rawMessage.pointee.event.trace
        
        self.target = Process(from: traceEvent.target.pointee, version: Int(rawMessage.pointee.version))
    }
}
