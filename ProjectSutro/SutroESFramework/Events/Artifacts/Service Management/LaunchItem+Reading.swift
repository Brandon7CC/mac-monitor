//
//  LaunchItem+Reading.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Reading a launch item from disk
extension LaunchItem {
    /// The item types whose item is a launchd plist.
    static let plistTypes = [ES_BTM_ITEM_TYPE_AGENT, ES_BTM_ITEM_TYPE_DAEMON]
    /// The item types whose item can be a bundle: an app, an `SMAppService` login item, or a user's login item.
    static let bundleTypes = [ES_BTM_ITEM_TYPE_APP, ES_BTM_ITEM_TYPE_LOGIN_ITEM, ES_BTM_ITEM_TYPE_USER_ITEM]

    /// The item's type, as the SDK's enum.
    var itemType: es_btm_item_type_t { es_btm_item_type_t(rawValue: UInt32(truncatingIfNeeded: item_type)) }

    /// An item's path on this Mac, absolute (``resolvedLocation(of:app:)``), as the event store's item names its plist
    /// (``ESLaunchItem/plistPath``).
    ///
    /// - Parameters:
    ///   - itemPath: ``item_path``.
    ///   - appPath: ``app_path``.
    /// - Returns: The path, or `nil` when the item has no path, or a relative one without an app.
    static func resolvedPath(of itemPath: String, app appPath: String?) -> String? {
        resolvedLocation(of: itemPath, app: appPath).map { $0.directory.appendingPathComponent($0.relativePath) }
    }

    /// Where an item is on this Mac: an absolute item path, as a legacy plist's and an app's are, is in its folder;
    /// another is relative to its app, as an `SMAppService` agent's plist or login item is
    /// (`Contents/Library/LoginItems/Helper.app`).
    ///
    /// - Parameters:
    ///   - itemPath: ``item_path``.
    ///   - appPath: ``app_path``.
    /// - Returns: The directory the item is in and its path there, or `nil` when the item has no path, or a relative
    ///   one without an app.
    static func resolvedLocation(of itemPath: String, app appPath: String?) -> (directory: String,
                                                                               relativePath: String)? {
        guard !itemPath.isEmpty else { return nil }
        if itemPath.hasPrefix("/") { return (itemPath.deletingLastPathComponent, itemPath.lastPathComponent) }
        return appPath.nonEmpty.map { ($0, itemPath) }
    }

    /// Read what the event doesn't carry from this Mac, as the Security Extension records it: an agent's or daemon's
    /// launchd plist, a bundle item's ``bundle`` and its Info.plist (both in ``plist_contents``), and the
    /// ``app_bundle`` of any item whose app is a bundle.
    ///
    /// Only at capture: ``enrich()`` never reads the disk. A plist stored in binary is kept as XML, and one reached
    /// through a symbolic link below its app or folder isn't read
    /// (``ProcessHelpers/getPropertyListContents(_:in:)``). On a remove, the item may already be gone, and then
    /// nothing is read.
    mutating func readFromDisk() {
        let app = app_path.nonEmpty.flatMap(LaunchItemBundle.read(at:))
        app_bundle = app?.bundle
        guard let location = Self.resolvedLocation(of: item_path, app: app_path) else { return }
        let path = location.directory.appendingPathComponent(location.relativePath)
        if Self.plistTypes.contains(itemType) {
            plist_contents = ProcessHelpers.getPropertyListContents(location.relativePath, in: location.directory)
        } else if Self.bundleTypes.contains(itemType) {
            /// An app item names its app: it's read once.
            let item = path == app?.bundle.path ? app : LaunchItemBundle.read(at: path)
            bundle = item?.bundle
            plist_contents = item?.infoPlist
        }
    }

    /// Derive the age at the event of the item's bundle and of its app's (``LaunchItemBundle/deriveAge(at:)``).
    ///
    /// - Parameter time: The message's time.
    mutating func deriveBundleAges(at time: Date) {
        bundle?.deriveAge(at: time)
        app_bundle?.deriveAge(at: time)
    }
}
