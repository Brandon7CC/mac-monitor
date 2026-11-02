//
//  PathMute.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import EndpointSecurity


// MARK: - Path mute
/// One path mute, as `es_mute_path` and `es_mute_path_events` take it (and their unmute counterparts).
public struct PathMute: Hashable, Sendable {
    /// The path, or path prefix, to match.
    public let path: String
    /// How ``path`` is matched: against the process or the target, literally or as a prefix.
    public let type: es_mute_path_type_t
    /// The events the mute is scoped to. Empty means every event.
    public let events: [es_event_type_t]
    
    /// - Parameters:
    ///   - path: The path, or path prefix, to match.
    ///   - type: How `path` is matched.
    ///   - events: The events to scope the mute to. Empty means every event.
    public init(path: String, type: es_mute_path_type_t, events: [es_event_type_t] = []) {
        self.path = path
        self.type = type
        self.events = events
    }
}


// MARK: - Mute set as mutes
extension MuteSet {
    /// Every rule as one mute per path: the event-specific rules first, then the global ones, in the order
    /// Endpoint Security clients have always had them applied.
    public var pathMutes: [PathMute] {
        let scoped = eventSpecificRules.flatMap { rule in
            rule.paths.map { PathMute(path: $0, type: rule.muteType, events: [rule.eventType]) }
        }
        let global = globalRules.flatMap { rule in rule.paths.map { PathMute(path: $0, type: rule.pathType) } }
        return scoped + global
    }
}
