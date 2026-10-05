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
    
    /// The mute types, by their `ES_MUTE_PATH_TYPE_*` names.
    private static let typesByName: [String: es_mute_path_type_t] = Dictionary(uniqueKeysWithValues: [
        ES_MUTE_PATH_TYPE_PREFIX, ES_MUTE_PATH_TYPE_LITERAL, ES_MUTE_PATH_TYPE_TARGET_PREFIX,
        ES_MUTE_PATH_TYPE_TARGET_LITERAL
    ].map { (getMuteCaseString(muteType: $0), $0) })
    
    /// - Parameters:
    ///   - path: The path, or path prefix, to match.
    ///   - type: How `path` is matched.
    ///   - events: The events to scope the mute to. Empty means every event.
    public init(path: String, type: es_mute_path_type_t, events: [es_event_type_t] = []) {
        self.path = path
        self.type = type
        self.events = events
    }
    
    /// What a mute read from the XPC contract does with an `ES_EVENT_TYPE_*` name Mac Monitor doesn't know.
    public enum UnknownEventNames: Sendable {
        /// Refuse the request, so a mute never covers fewer events than it names.
        case refuse
        /// Leave the name out, for unmuting. The events Endpoint Security lists for a muted path
        /// (`es_muted_paths_events`) can include types Mac Monitor has no name for, which it lists as
        /// `ES_EVENT_TYPE_LAST`: refusing those would leave the path muted. The types Mac Monitor names are unmuted, as
        /// they were when such a name went through as `ES_EVENT_TYPE_LAST`, which Endpoint Security skips; the
        /// unnamed ones stay muted either way.
        case drop
    }
    
    /// A mute from the names the XPC contract carries.
    ///
    /// Stricter than `getMuteCaseFromString(muteString:)`, which reads an unknown name as `TARGET_PREFIX`, and
    /// `eventStringToType(from:)`, which reads one as `ES_EVENT_TYPE_LAST`: a request with a type name Mac Monitor
    /// doesn't know is refused rather than applied as some other mute, and so is one with an unknown event name unless
    /// `unknownEvents` is ``UnknownEventNames/drop``.
    ///
    /// - Parameters:
    ///   - path: The path, or path prefix, to match.
    ///   - typeName: The `ES_MUTE_PATH_TYPE_*` name.
    ///   - eventNames: `ES_EVENT_TYPE_*` names to scope the mute to. Empty means every event.
    ///   - unknownEvents: Refuse the request when an event name is unknown, or leave the name out.
    /// - Returns: `nil` for an empty path or an unknown type name, and for an unknown event name when refusing them.
    ///   When dropping them, `nil` if none of the names is known: an empty list would mean every event.
    public init?(path: String, typeName: String, eventNames: [String], unknownEvents: UnknownEventNames = .refuse) {
        let named = eventNames.map { eventStringToType(from: $0) }
        let events = named.filter { $0 != ES_EVENT_TYPE_LAST }
        guard !path.isEmpty, let type = Self.typesByName[typeName],
              events.count == named.count || (unknownEvents == .drop && !events.isEmpty) else {
            return nil
        }
        self.init(path: path, type: type, events: events)
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
