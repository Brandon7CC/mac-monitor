//
//  MuteList.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Mute scope
/// The events a saved mute covers.
public enum MuteScope: Hashable, Sendable {
    /// Every event (`es_mute_path`).
    case allEvents
    /// Only these events (`es_mute_path_events`). Never empty.
    case events(Set<es_event_type_t>)
}


// MARK: - Mute list
/// Path mutes as values: at most one ``MuteScope`` per path and type, the way Endpoint Security keeps its mutes as
/// (type, path, event) tuples (`ESClient.h`, `es_unmute_path`). The saved mute set is one of these.
public struct MuteList: Equatable, Sendable {
    /// A path and how it's matched.
    public struct Key: Hashable, Comparable, Sendable {
        /// The path, or path prefix.
        public let path: String
        /// How ``path`` is matched: against the process or the target, literally or as a prefix.
        public let type: es_mute_path_type_t
        
        /// - Parameters:
        ///   - path: The path, or path prefix.
        ///   - type: How `path` is matched.
        public init(path: String, type: es_mute_path_type_t) {
            self.path = path
            self.type = type
        }
        
        /// Canonical order: by `ES_MUTE_PATH_TYPE_*` name, then by path.
        ///
        /// - Parameters:
        ///   - lhs: A key.
        ///   - rhs: Another key.
        /// - Returns: `true` if `lhs` comes first.
        public static func < (lhs: Key, rhs: Key) -> Bool {
            (getMuteCaseString(muteType: lhs.type), lhs.path) < (getMuteCaseString(muteType: rhs.type), rhs.path)
        }
    }
    
    /// Each muted path's events.
    public private(set) var scopes: [Key: MuteScope] = [:]
    
    /// An empty list.
    public init() {}
    
    /// A list of mutes, merged by path and type.
    ///
    /// - Parameter mutes: The mutes. Empty events means every event.
    public init(_ mutes: [PathMute]) {
        mutes.forEach { add($0) }
    }
    
    /// Mac Monitor's default mute set (``MuteSet/default(home:)``) for a console user: what Reset restores and a new
    /// saved set starts from.
    ///
    /// - Parameter user: Whose home folder's caches and Biome streams are muted. Without one, those mutes are left out.
    /// - Returns: The list.
    public static func shippedDefault(for user: ConsoleUser?) -> MuteList {
        MuteList(MuteSet.default(home: user?.home).pathMutes)
    }
    
    /// Mac Monitor's default mute set for whoever is logged in at the console now (``ConsoleUser/current(_:)``), as
    /// the Security Extension makes it.
    public static var shippedDefault: MuteList {
        shippedDefault(for: .current())
    }
    
    /// How many paths are muted.
    public var count: Int { scopes.count }
    
    /// Is nothing muted?
    public var isEmpty: Bool { scopes.isEmpty }
    
    /// The keys, in canonical order.
    public var keys: [Key] { scopes.keys.sorted() }
    
    /// One mute per path, in canonical order (type name, then path), its events in name order. An empty event list
    /// means every event.
    public var mutes: [PathMute] {
        keys.compactMap { mute(for: $0) }
    }
    
    /// One path's mute, its events in name order.
    ///
    /// - Parameter key: The path and type.
    /// - Returns: The mute, or `nil` if the path isn't muted with that type.
    public func mute(for key: Key) -> PathMute? {
        switch scopes[key] {
        case .allEvents?:
            return PathMute(path: key.path, type: key.type)
        case .events(let events)?:
            return PathMute(path: key.path, type: key.type, events: Self.sorted(events))
        case nil:
            return nil
        }
    }
    
    /// Mute more: a path's events grow, and every event absorbs any list.
    ///
    /// - Parameter mute: The mute. Empty events means every event.
    /// - Returns: `true` if the list changed.
    @discardableResult
    public mutating func add(_ mute: PathMute) -> Bool {
        let key = Key(path: mute.path, type: mute.type), old = scopes[key]
        switch old {
        case .allEvents?:
            return false
        case .events(let events)? where !mute.events.isEmpty:
            scopes[key] = .events(events.union(mute.events))
        case nil where !mute.events.isEmpty:
            scopes[key] = .events(Set(mute.events))
        default:
            scopes[key] = .allEvents
        }
        return scopes[key] != old
    }
    
    /// Mute everything another list mutes.
    ///
    /// - Parameter list: The other list.
    /// - Returns: `true` if this list changed.
    @discardableResult
    public mutating func add(contentsOf list: MuteList) -> Bool {
        list.mutes.reduce(false) { changed, mute in add(mute) || changed }
    }
    
    /// Unmute: no events removes the path; events remove only those, and the path once none is left. Unmuting what
    /// isn't muted changes nothing, as in Endpoint Security.
    ///
    /// - Parameter mute: The path, its type, and the events to unmute (none for every event).
    /// - Returns: `true` if the list changed.
    /// - Throws: ``MuteListError/narrowsAllEvents(path:type:)`` for some events of a path muted for every event. The
    ///   list is left as it was.
    @discardableResult
    public mutating func remove(_ mute: PathMute) throws -> Bool {
        let key = Key(path: mute.path, type: mute.type)
        guard let old = scopes[key] else { return false }
        guard !mute.events.isEmpty else {
            scopes[key] = nil
            return true
        }
        guard case .events(let events) = old else {
            throw MuteListError.narrowsAllEvents(path: mute.path, type: mute.type)
        }
        let left = events.subtracting(mute.events)
        scopes[key] = left.isEmpty ? nil : .events(left)
        return left != events
    }
    
    /// Events in name order, the order mute files and Endpoint Security calls use.
    ///
    /// - Parameter events: Some events.
    /// - Returns: The events, sorted by `ES_EVENT_TYPE_*` name, then by value.
    static func sorted(_ events: Set<es_event_type_t>) -> [es_event_type_t] {
        events.sorted { (eventTypeToString(from: $0), $0.rawValue) < (eventTypeToString(from: $1), $1.rawValue) }
    }
}


// MARK: - Errors
/// Why a change to a ``MuteList`` was refused.
public enum MuteListError: Error, Equatable, CustomStringConvertible {
    /// Unmuting some events of a path muted for every event. Endpoint Security would leave every other event muted,
    /// including events later macOS versions add, which a list of events can't describe.
    case narrowsAllEvents(path: String, type: es_mute_path_type_t)
    
    /// The refusal, as a sentence for Mac Monitor and `macmonitor` to show.
    public var description: String {
        switch self {
        case .narrowsAllEvents(let path, let type):
            return """
                “\(path)” (\(getMuteCaseString(muteType: type))) is muted for every event, so single events can't be \
                unmuted. Remove it, then add it back for the events you want muted.
                """
        }
    }
}
