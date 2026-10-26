//
//  MutedPath.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/7/22.
//

import Foundation
import EndpointSecurity


public struct ESMutedPath: Identifiable, Codable, Hashable {
    public var id: String { "\(path)-\(type)" }
    public var type: String
    public var events: [String]
    public var path: String
    public var eventCount: Int
    
    /// A mute Endpoint Security reports, with the events the mute was requested for.
    ///
    /// - Parameter rawPath: The muted path.
    init(fromRawESPath rawPath: es_muted_path_t) {
        let events = UnsafeBufferPointer(start: rawPath.events, count: rawPath.event_count)
        self.init(type: getMuteCaseString(muteType: rawPath.type), events: events.map { eventTypeToString(from: $0) },
                  path: rawPath.path.string ?? "")
    }
    
    public init(type: String, events: [String], path: String) {
        self.type = type
        self.events = events
        self.path = path
        self.eventCount = events.count
    }
    
    /// A saved mute set entry, as the list shows it. No events means every event.
    ///
    /// - Parameter entry: The entry.
    public init(_ entry: MuteFile.Entry) {
        self.init(type: entry.type, events: entry.events, path: entry.path)
    }
}
