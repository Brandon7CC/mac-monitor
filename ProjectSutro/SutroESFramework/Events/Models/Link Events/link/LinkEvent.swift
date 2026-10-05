//
//  LinkEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/1/23.
//

import Foundation
import EndpointSecurity

/// https://developer.apple.com/documentation/endpointsecurity/es_event_link_t
/// A type for an event that indicates the creation of a hard link.
///
public struct LinkEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    public var source, target_dir: File
    public var target_filename: String
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: LinkEvent, rhs: LinkEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the file write event
        let event: es_event_link_t = rawMessage.pointee.event.link
        
        source = File(from: event.source.pointee)
        target_dir = File(from: event.target_dir.pointee)
        target_filename = event.target_filename.string ?? ""
    }
}
