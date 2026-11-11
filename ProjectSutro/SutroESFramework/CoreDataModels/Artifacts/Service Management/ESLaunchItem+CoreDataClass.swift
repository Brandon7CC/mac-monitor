//
//  ESLaunchItem+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 9/26/25.
//
//

import Foundation
import CoreData


@objc(ESLaunchItem)
public class ESLaunchItem: NSManagedObject, Identifiable {
    @NSManaged public var item_type: Int16
    @NSManaged public var item_type_string: String
    @NSManaged public var item_url: String
    @NSManaged public var item_path: String
    @NSManaged public var app_url: String?
    @NSManaged public var app_path: String?
    @NSManaged public var legacy: Bool
    @NSManaged public var managed: Bool
    @NSManaged public var uid: Int64
    @NSManaged public var plist_contents: String?
    @NSManaged public var uid_human: String?
    /// ``bundle`` as JSON: `nil` when the item has none.
    @NSManaged public var bundleData: Data?
    /// ``app_bundle`` as JSON: `nil` when the item has none.
    @NSManaged public var appBundleData: Data?

    enum CodingKeys: CodingKey {
        case item_type
        case item_type_string
        case item_url
        case item_path
        case app_url
        case app_path
        case legacy
        case managed
        case uid
        case uid_human
        case plist_contents
        case bundle
        case app_bundle
    }
    
    /// The bundle the item names (``LaunchItem/bundle``), kept as JSON in ``bundleData``.
    public var bundle: LaunchItemBundle? {
        get { Self.decodeBundle(bundleData) }
        set { bundleData = Self.encodeBundle(newValue) }
    }
    
    /// The bundle of the item's app (``LaunchItem/app_bundle``), kept as JSON in ``appBundleData``.
    public var app_bundle: LaunchItemBundle? {
        get { Self.decodeBundle(appBundleData) }
        set { appBundleData = Self.encodeBundle(newValue) }
    }
    
    /// The path of the property list ``plist_contents`` holds, as Event Facts names it: a bundle item's Info.plist, as
    /// it was read (``LaunchItemBundle/info_plist_path``, else `Contents/Info.plist` in a record that doesn't name it),
    /// otherwise the item's path on the Mac that recorded it, absolute (``LaunchItem/resolvedPath(of:app:)``): an
    /// `SMAppService` agent's plist is relative to its app.
    public var plistPath: String {
        if let bundle { return bundle.info_plist_path ?? LaunchItemBundle.Layout.deep.infoPlistPath(in: bundle.path) }
        return LaunchItem.resolvedPath(of: item_path, app: app_path) ?? item_path
    }

    /// A bundle from its stored JSON.
    ///
    /// - Parameter data: The JSON, or `nil`.
    /// - Returns: The bundle, or `nil` when there's none or it doesn't decode.
    private static func decodeBundle(_ data: Data?) -> LaunchItemBundle? {
        data.flatMap { try? JSONDecoder().decode(LaunchItemBundle.self, from: $0) }
    }
    
    /// A bundle's JSON, to store.
    ///
    /// - Parameter bundle: The bundle, or `nil`.
    /// - Returns: The JSON, or `nil` when there's no bundle.
    private static func encodeBundle(_ bundle: LaunchItemBundle?) -> Data? {
        bundle.flatMap { try? JSONEncoder().encode($0) }
    }
    
    // MARK: - Custom Core Data initilizer for ESLaunchItem
    convenience init(
        from launchItem: LaunchItem,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        self.init(insertingInto: context)
        
        self.item_type = launchItem.item_type
        self.item_type_string = launchItem.item_type_string
        self.item_url = launchItem.item_url
        self.item_path = launchItem.item_path
        self.app_url = launchItem.app_url
        self.app_path = launchItem.app_path
        self.legacy = launchItem.legacy
        self.managed = launchItem.managed
        self.uid = launchItem.uid
        self.uid_human = launchItem.uid_human
        self.plist_contents = launchItem.plist_contents
        self.bundle = launchItem.bundle
        self.app_bundle = launchItem.app_bundle
    }
}

// MARK: - Encodable conformance and helper
extension ESLaunchItem: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(item_type, forKey: .item_type)
        try container.encode(item_type_string, forKey: .item_type_string)
        try container.encode(item_url, forKey: .item_url)
        try container.encode(item_path, forKey: .item_path)
        try container.encode(app_url, forKey: .app_url)
        try container.encode(app_path, forKey: .app_path)
        try container.encode(legacy, forKey: .legacy)
        try container.encode(managed, forKey: .managed)
        try container.encode(uid, forKey: .uid)
        try container.encode(uid_human, forKey: .uid_human)
        try container.encodeIfPresent(plist_contents, forKey: .plist_contents)
        /// Always written: `null` when the item names no bundle, or it was gone.
        try container.encode(bundle.map(ExportedLaunchItemBundle.init), forKey: .bundle)
        try container.encode(app_bundle.map(ExportedLaunchItemBundle.init), forKey: .app_bundle)
    }
}
