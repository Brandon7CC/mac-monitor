//
//  MuteList+Changes.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Mute change
/// One Endpoint Security call that moves a client's path mutes toward another list.
public struct MuteChange: Equatable, Sendable {
    /// The path, its type, and the one event to change (none for every event).
    public let mute: PathMute
    /// `true` to mute, `false` to unmute.
    public let muted: Bool
    
    /// - Parameters:
    ///   - mute: The path, its type, and the one event to change (none for every event).
    ///   - muted: `true` to mute, `false` to unmute.
    public init(_ mute: PathMute, muted: Bool) {
        self.mute = mute
        self.muted = muted
    }
}


// MARK: - Difference
/// How two lists differ, mute by mute (a path and its type), each kind in canonical order.
public struct MuteListDifference: Equatable, Sendable {
    /// Paths and types only the new list mutes.
    public let added: [MuteList.Key]
    /// Paths and types only the old list mutes.
    public let removed: [MuteList.Key]
    /// Paths and types both lists mute, for different events.
    public let changed: [MuteList.Key]
    
    /// Do the lists mute the same?
    public var isEmpty: Bool {
        added.isEmpty && removed.isEmpty && changed.isEmpty
    }
}


// MARK: - Changes between lists
extension MuteList {
    /// How `next` differs from this list, mute by mute.
    ///
    /// - Parameter next: The list after a change.
    /// - Returns: The mutes added, removed, and changed.
    public func difference(to next: MuteList) -> MuteListDifference {
        MuteListDifference(added: next.keys.filter { scopes[$0] == nil },
                           removed: keys.filter { next.scopes[$0] == nil },
                           changed: next.keys.filter { key in scopes[key].map { $0 != next.scopes[key] } ?? false })
    }
    
    /// The calls that turn this list's mutes on a client into `target`'s, key by key in canonical order.
    ///
    /// Each call names one event, or none for every event (`es_mute_path`, `es_unmute_path`), so an event a client
    /// refuses never takes others with it. Endpoint Security keeps mutes as (type, path, event) tuples and unmuting is
    /// a set subtraction (`ESClient.h`), so for each key:
    /// - New: mute its events. Gone: unmute them.
    /// - Some events to others: mute the new ones before unmuting the old ones, so nothing both lists mute is ever
    ///   left unmuted.
    /// - Some events to every event: mute every event and nothing else. Unmuting the old events afterwards would
    ///   subtract them from every event.
    /// - Every event to some: unmute every event, then mute the new ones. The only change that briefly unmutes what
    ///   both lists mute; a list only narrows that way when it's replaced or reset.
    ///
    /// - Parameter target: The list the client should end up with.
    /// - Returns: The calls, in order. None if the lists are equal.
    public func changes(to target: MuteList) -> [MuteChange] {
        Set(scopes.keys).union(target.scopes.keys).sorted().flatMap { key in
            Self.changes(for: key, from: scopes[key], to: target.scopes[key])
        }
    }
    
    /// The calls for one key.
    ///
    /// - Parameters:
    ///   - key: The path and type.
    ///   - old: Its scope now, if it's muted.
    ///   - new: Its scope to be, if it's to stay muted.
    /// - Returns: The calls, in order.
    private static func changes(for key: Key, from old: MuteScope?, to new: MuteScope?) -> [MuteChange] {
        switch (old, new) {
        case (nil, nil):
            return []
        case (nil, let new?):
            return calls(key, new, muted: true)
        case (let old?, nil):
            return calls(key, old, muted: false)
        case (.allEvents?, .allEvents?):
            return []
        case (.events?, .allEvents?):
            return calls(key, .allEvents, muted: true)
        case (.allEvents?, let new?):
            return calls(key, .allEvents, muted: false) + calls(key, new, muted: true)
        case (.events(let before)?, .events(let after)?):
            return calls(key, after.subtracting(before), muted: true)
                + calls(key, before.subtracting(after), muted: false)
        }
    }
    
    /// One call per event of a scope, in name order, or one for every event.
    ///
    /// - Parameters:
    ///   - key: The path and type.
    ///   - scope: The events.
    ///   - muted: `true` to mute, `false` to unmute.
    /// - Returns: The calls.
    private static func calls(_ key: Key, _ scope: MuteScope, muted: Bool) -> [MuteChange] {
        guard case .events(let events) = scope else {
            return [MuteChange(PathMute(path: key.path, type: key.type), muted: muted)]
        }
        return calls(key, events, muted: muted)
    }
    
    /// One call per event, in name order.
    ///
    /// - Parameters:
    ///   - key: The path and type.
    ///   - events: The events. None makes no calls.
    ///   - muted: `true` to mute, `false` to unmute.
    /// - Returns: The calls.
    private static func calls(_ key: Key, _ events: Set<es_event_type_t>, muted: Bool) -> [MuteChange] {
        sorted(events).map { MuteChange(PathMute(path: key.path, type: key.type, events: [$0]), muted: muted) }
    }
}
