//
//  ProcessExitEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation


// MARK: - Process Exit event: https://developer.apple.com/documentation/endpointsecurity/es_event_exit_t
public struct ProcessExitEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    /// stat The exit status of a process (same format as wait(2))
    public var stat: Int
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(stat)
    }
    
    public static func == (lhs: ProcessExitEvent, rhs: ProcessExitEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let exitEvent: es_event_exit_t = rawMessage.pointee.event.exit
        self.stat = Int(exitEvent.stat)
    }
}
