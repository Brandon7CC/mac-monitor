//
//  ESLaunchItemAddEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData

@objc(ESLaunchItemAddEvent)
public class ESLaunchItemAddEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case instigator
        case app
        case item
        case executable_path
        case instigator_token, app_token
    }
    
    // MARK: - Custom Core Data initilizer for ESLaunchItemAddEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: LaunchItemAddEvent = message.event.btm_launch_item_add!
        let description = NSEntityDescription.entity(forEntityName: "ESLaunchItemAddEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = event.id
        let version: Int = message.version
        
        if let instigator = event.instigator {
            self.instigator = ESProcess(
                from: instigator,
                version: version,
                insertIntoManagedObjectContext: context
            )
        }
        
        if let app = event.app {
            self.app = ESProcess(
                from: app,
                version: version,
                insertIntoManagedObjectContext: context
            )
        }
        
        item = ESLaunchItem(from: event.item, insertIntoManagedObjectContext: context)
        
        executable_path = event.executable_path
        if let instigator_token = event.instigator_token {
            self.instigator_token = ESAuditToken(from: instigator_token, insertIntoManagedObjectContext: context)
        }
        
        if let app_token = event.app_token {
            self.app_token = ESAuditToken(from: app_token, insertIntoManagedObjectContext: context)
        }
    }
}

// MARK: - Encodable conformance
extension ESLaunchItemAddEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        //        try container.encode(id, forKey: .id)
        try container.encode(instigator, forKey: .instigator)
        try container.encode(app, forKey: .app)
        try container.encode(item, forKey: .item)
        try container.encode(executable_path, forKey: .executable_path)
        
        try container.encode(instigator_token, forKey: .instigator_token)
        try container.encode(app_token, forKey: .app_token)
        
    }
    
    public var itemName: String? {
        if let url = URL(string: item.item_url) {
            return url.lastPathComponent
        }
        return nil
    }
}
