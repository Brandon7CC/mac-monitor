//
//  MuteSetUpgrade.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import EndpointSecurity


// MARK: - Upgrading a saved set
/// What a saved mute set becomes when a newer Mac Monitor has changed its default set (``MuteSet/revisions``).
///
/// The saved set is compared with the default set it started from, its base: the default set of its revision, for
/// the home folder its per-user mutes cover, with or without Xcode's mutes, and with or without the XPC connect mutes
/// macOS 13 doesn't have. A set saved without a revision (by 3.0, or by 3.0 after a downgrade) is compared with every
/// revision's, and the closest is its base.
/// - **Unchanged:** it's the base exactly, so it becomes the current default set. ``SavedMuteSet`` does that without
///   asking, when it loads.
/// - **Changed:** the default set's changes since the base are merged in (``MuteList/merging(defaultsFrom:to:)``),
///   keeping the user's own. That's only done when asked: Mac Monitor offers it, and `macmonitor mute update` does it.
///
/// Neither ever adds Xcode's mutes to a set without them: a set whose only change is unmuting Xcode looks exactly
/// like one made before Xcode was installed. They're only dropped, when root no longer owns Xcode. Reset adds them.
struct MuteSetUpgrade: Equatable {
    /// The saved set with the current default set merged in.
    let merged: MuteList
    /// Was the saved set its base, unchanged? Then it's updated without asking.
    let wasDefault: Bool
    /// The base's revision: the saved set's own, or the closest one for a set saved without it.
    let revision: Int
    
    /// - Parameters:
    ///   - saved: The saved set.
    ///   - revision: The default set revision it was last brought up to, or `nil` if it wasn't saved with one.
    ///   - mutesXcode: Does the current default set mute Xcode's tools? By default, if root owns Xcode.
    /// - Returns: The upgrade, or `nil` if the set is at the current revision or a newer one, or closest to it.
    static func plan(for saved: MuteList, revision: Int?,
                     mutesXcode: Bool = MuteSet.ownsXcode()) -> MuteSetUpgrade? {
        let current = MuteSet.currentRevision
        if let revision, revision >= current { return nil }
        let home = homeFolder(of: saved)
        let candidates = bases(home: home, revisions: revision.map { [$0] } ?? Array((1...current).reversed()),
                               mutesXcode: mutesXcode)
        let base = candidates.first { $0.list == saved } ?? candidates.min {
            size(of: saved.difference(to: $0.list)) < size(of: saved.difference(to: $1.list))
        }
        guard let base, base.revision < current else { return nil }
        let target = MuteList(MuteSet.default(home: home, mutesXcode: base.mutesXcode && mutesXcode).pathMutes)
        let wasDefault = base.list == saved
        return MuteSetUpgrade(merged: wasDefault ? target : saved.merging(defaultsFrom: base.list, to: target),
                              wasDefault: wasDefault, revision: base.revision)
    }
    
    /// The default sets a saved set may have started from: each revision's, with and without Xcode's mutes, and on
    /// macOS 14 and later without the XPC connect mutes too. Today's Xcode answer, then the newest revision, first.
    ///
    /// - Parameters:
    ///   - home: The home folder its per-user mutes cover.
    ///   - revisions: The revisions to try, in order.
    ///   - mutesXcode: Does the current default set mute Xcode's tools?
    /// - Returns: Each candidate, its revision, and whether it mutes Xcode.
    private static func bases(home: String?, revisions: [Int], mutesXcode: Bool)
        -> [(list: MuteList, revision: Int, mutesXcode: Bool)] {
        let systems = MuteSet.hasXPCConnects ? [true, false] : [false]
        return revisions.flatMap { revision in
            [mutesXcode, !mutesXcode].flatMap { xcode in
                systems.map { xpc in
                    (MuteList.shippedDefault(home: home, mutesXcode: xcode, mutesXPCConnects: xpc, revision: revision),
                     revision, xcode)
                }
            }
        }
    }
    
    /// The home folder a saved set's per-user mutes cover: the folder its caches mute, or its Biome streams mute,
    /// sits in.
    ///
    /// - Parameter list: The saved set.
    /// - Returns: The home folder, or `nil` if it has neither mute, as a set made with no one logged in hasn't.
    static func homeFolder(of list: MuteList) -> String? {
        for (suffix, event) in [("/Library/Caches/", ES_EVENT_TYPE_NOTIFY_CREATE),
                                ("/Library/Biome/streams/", ES_EVENT_TYPE_NOTIFY_GETEXTATTR)] {
            let key = list.keys.first { key in
                guard key.type == ES_MUTE_PATH_TYPE_TARGET_PREFIX, key.path.hasSuffix(suffix),
                      case .events(let events)? = list.scopes[key] else { return false }
                return events.contains(event)
            }
            if let key { return String(key.path.dropLast(suffix.count)) }
        }
        return nil
    }

    /// How many mutes a difference touches.
    ///
    /// - Parameter difference: The difference.
    /// - Returns: Mutes added, removed and changed.
    private static func size(of difference: MuteListDifference) -> Int {
        difference.added.count + difference.removed.count + difference.changed.count
    }
}


// MARK: - Merging the default set's changes
extension MuteList {
    /// This set with the default set's changes from `base` to `new` applied: what a saved set someone has changed
    /// becomes when it's updated. For each path and type the default set changed:
    /// - This set has it as `base` did: it becomes what `new` has.
    /// - The user changed it too: the events `new` added are added and the ones it dropped are dropped, so the
    ///   user's own additions and removals stay. A path they unmuted gets back only the events `new` added.
    /// - A mute of every event: the user's is kept, and one `new` adds is taken.
    ///
    /// - Parameters:
    ///   - base: The default set this set started from.
    ///   - new: The current default set.
    /// - Returns: The merged set.
    func merging(defaultsFrom base: MuteList, to new: MuteList) -> MuteList {
        var merged = scopes
        for key in Set(base.scopes.keys).union(new.scopes.keys) where base.scopes[key] != new.scopes[key] {
            merged[key] = Self.merge(scopes[key], from: base.scopes[key], to: new.scopes[key])
        }
        return MuteList(merged.map { key, scope in
            switch scope {
            case .allEvents: return PathMute(path: key.path, type: key.type)
            case .events(let events): return PathMute(path: key.path, type: key.type, events: Self.sorted(events))
            }
        })
    }

    /// One path and type's merge.
    ///
    /// - Parameters:
    ///   - saved: The saved set's scope, if it mutes the path.
    ///   - base: The base default set's.
    ///   - new: The current default set's.
    /// - Returns: The merged scope, or `nil` to leave the path unmuted.
    private static func merge(_ saved: MuteScope?, from base: MuteScope?, to new: MuteScope?) -> MuteScope? {
        if saved == base { return new }
        switch (saved, base, new) {
        case (_, _, .allEvents?), (.allEvents?, _, _), (_, .allEvents?, _):
            return new == .allEvents ? .allEvents : saved
        default:
            let (mine, before, after) = (events(saved), events(base), events(new))
            let events = mine.union(after.subtracting(before)).subtracting(before.subtracting(after))
            return events.isEmpty ? nil : .events(events)
        }
    }

    /// A scope's events: none when the path isn't muted. Never called for a mute of every event.
    ///
    /// - Parameter scope: The scope.
    /// - Returns: Its events.
    private static func events(_ scope: MuteScope?) -> Set<es_event_type_t> {
        if case .events(let events)? = scope { return events }
        return []
    }
}
