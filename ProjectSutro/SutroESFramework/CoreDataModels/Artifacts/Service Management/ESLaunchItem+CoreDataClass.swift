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
    }
    
    // MARK: - Custom Core Data initilizer for ESLaunchItem
    convenience init(
        from launchItem: LaunchItem,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        let description = NSEntityDescription.entity(forEntityName: "ESLaunchItem", in: context)!
        self.init(entity: description, insertInto: context)
        
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
    }
}
