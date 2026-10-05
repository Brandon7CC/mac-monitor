//
//  ProcessForkEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 1/13/23.
//

import Foundation


// MARK: - Process Fork Event https://developer.apple.com/documentation/endpointsecurity/es_event_fork_t
public struct ProcessForkEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    
    public var child: Process
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: ProcessForkEvent, rhs: ProcessForkEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let forkEvent: es_event_fork_t = rawMessage.pointee.event.fork
        
        self.child = Process(from: forkEvent.child.pointee, version: Int(rawMessage.pointee.version))
    }
}
