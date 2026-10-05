//
//  FDDuplicateEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 2/16/23.
//

import Foundation


// https://developer.apple.com/documentation/endpointsecurity/es_event_dup_t
public struct FDDuplicateEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    public var target: File
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: FDDuplicateEvent, rhs: FDDuplicateEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>, shouldCheckQuarantine: Bool = false) {
        let event: es_event_dup_t = rawMessage.pointee.event.dup
        
        target = File(from: event.target.pointee)
    }
}
