//
//  MuteSet+Revisions.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import EndpointSecurity


// MARK: - Default set revisions
/// Each release's changes to Mac Monitor's default mute set, so a saved set can be brought up to date when Mac
/// Monitor is upgraded (``MuteSetUpgrade``).
///
/// The saved set records the revision it was last brought up to (``MuteFile/defaultsRevision``). A set saved before
/// revisions were recorded is revision 1: the 3.0 default set. To find the default set a saved set started from, the
/// current default set is walked back: each later revision's additions are taken out and its removals put back.
///
/// **Changing the default set:** add a revision here with exactly what changed. `DefaultMuteSetRevisionTests` fails
/// until the newest revision describes ``MuteSet/default(home:mutesXcode:mutesXPCConnects:)``. Revision 3 changes a
/// per-user mute, so the revisions are made for a home folder (``revisions(home:)``). None so far changes Xcode's
/// mutes. One that does needs Xcode's mutes passed in too.
extension MuteSet {
    /// One release's changes to the default set.
    struct Revision {
        /// Counts up from 1, the 3.0 set.
        let number: Int
        /// The release it shipped in, such as "3.1", for messages.
        let release: String
        /// Mutes it added. Events added to a path the set already muted for others are listed alone.
        let added: [PathMute]
        /// Mutes it took away.
        let removed: [PathMute]
    }

    /// Every revision after the 3.0 set, oldest first, without the per-user mutes: their numbers and releases.
    static let revisions = revisions(home: nil)

    /// Every revision after the 3.0 set, oldest first, for one home folder.
    ///
    /// - Parameter home: The home folder the per-user mutes cover, or `nil` to leave them out.
    /// - Returns: The revisions.
    static func revisions(home: String?) -> [Revision] { [
        Revision(number: 2, release: "3.1", added: [
            mute("/usr/libexec/spotlightknowledged.updater", ES_MUTE_PATH_TYPE_LITERAL,
                 ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_MPROTECT),
            mute("/usr/libexec/dasd", ES_MUTE_PATH_TYPE_LITERAL, ES_EVENT_TYPE_NOTIFY_CREATE,
                 ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_SETMODE,
                 ES_EVENT_TYPE_NOTIFY_XPC_CONNECT),
            mute("/usr/libexec/logd_helper", ES_MUTE_PATH_TYPE_LITERAL, ES_EVENT_TYPE_NOTIFY_CREATE,
                 ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_SETMODE),
            mute("/usr/libexec/swcd", ES_MUTE_PATH_TYPE_LITERAL, ES_EVENT_TYPE_NOTIFY_MMAP),
            mute("/usr/libexec/xpcproxy", ES_MUTE_PATH_TYPE_LITERAL, ES_EVENT_TYPE_NOTIFY_XPC_CONNECT),
            mute("/System/Library/CoreServices/WiFiAgent.app/Contents/MacOS/WiFiAgent", ES_MUTE_PATH_TYPE_LITERAL,
                 ES_EVENT_TYPE_NOTIFY_XPC_CONNECT),
            mute("/usr/libexec/UserEventAgent", ES_MUTE_PATH_TYPE_LITERAL, ES_EVENT_TYPE_NOTIFY_XPC_CONNECT),
            mute("/dev/ttys", ES_MUTE_PATH_TYPE_TARGET_PREFIX, ES_EVENT_TYPE_NOTIFY_CLOSE),
            mute("/dev/console", ES_MUTE_PATH_TYPE_TARGET_LITERAL, ES_EVENT_TYPE_NOTIFY_CLOSE),
            mute("/private/var/log/com.apple.xpc.launchd/launchd.log", ES_MUTE_PATH_TYPE_TARGET_LITERAL,
                 ES_EVENT_TYPE_NOTIFY_CLOSE),
            mute("/usr/libexec/seputil", ES_MUTE_PATH_TYPE_TARGET_LITERAL, ES_EVENT_TYPE_NOTIFY_MMAP),
            mute("/usr/sbin/bluetoothd", ES_MUTE_PATH_TYPE_TARGET_LITERAL, ES_EVENT_TYPE_NOTIFY_MMAP),
            mute("/System/Library/Caches/com.apple.coresymbolicationd/data", ES_MUTE_PATH_TYPE_TARGET_LITERAL,
                 ES_EVENT_TYPE_NOTIFY_MMAP),
            mute("/System/Library/PrivateFrameworks/MediaAnalysis.framework/Versions/A/Resources/",
                 ES_MUTE_PATH_TYPE_TARGET_PREFIX, ES_EVENT_TYPE_NOTIFY_MMAP)
        ], removed: [
            mute("/usr/sbin/cfprefsd", ES_MUTE_PATH_TYPE_LITERAL, ES_EVENT_TYPE_NOTIFY_RENAME)
        ]),
        /// Closes in the user's caches, where creates and renames were muted already.
        Revision(number: 3, release: "3.1", added: homePaths("Library/Caches", in: home).map {
            mute($0, ES_MUTE_PATH_TYPE_TARGET_PREFIX, ES_EVENT_TYPE_NOTIFY_CLOSE)
        }, removed: [])
    ] }

    /// The default set's revision: what Reset, a first run and an update save.
    public static var currentRevision: Int { revisions.last?.number ?? 1 }

    /// The release that last changed the default set after a revision, such as "3.1".
    ///
    /// - Parameter revision: A saved set's revision.
    /// - Returns: The newest release's name.
    static func release(after revision: Int) -> String {
        revisions.last { $0.number > revision }?.release ?? revisions.last?.release ?? "3.0"
    }

    /// One mute, for the revisions.
    ///
    /// - Parameters:
    ///   - path: The path or prefix.
    ///   - type: How it's matched.
    ///   - events: Its events.
    /// - Returns: The mute.
    private static func mute(_ path: String, _ type: es_mute_path_type_t, _ events: es_event_type_t...) -> PathMute {
        PathMute(path: path, type: type, events: events)
    }
}


// MARK: - Earlier default sets
extension MuteList {
    /// Mac Monitor's default mute set as an earlier revision had it, walked back from the current one.
    ///
    /// - Parameters:
    ///   - home: The home folder its per-user mutes cover, if any.
    ///   - mutesXcode: Mute Xcode's tools.
    ///   - mutesXPCConnects: Include the XPC connect mutes, which macOS 13 doesn't have. By default, on macOS 14 and
    ///     later.
    ///   - revision: The revision, 1 for the 3.0 set.
    /// - Returns: The set.
    static func shippedDefault(home: String?, mutesXcode: Bool, mutesXPCConnects: Bool? = nil,
                               revision: Int) -> MuteList {
        let set = MuteSet.default(home: home, mutesXcode: mutesXcode, mutesXPCConnects: mutesXPCConnects)
        var list = MuteList(set.pathMutes)
        for change in MuteSet.revisions(home: home).reversed() where change.number > revision {
            /// Only events are named, and no revision touches a mute of every event, so a removal never throws.
            change.added.forEach { _ = try? list.remove($0) }
            change.removed.forEach { list.add($0) }
        }
        return list
    }
}
