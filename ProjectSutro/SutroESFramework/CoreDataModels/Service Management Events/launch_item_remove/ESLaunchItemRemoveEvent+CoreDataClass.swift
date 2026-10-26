//
//  ESLaunchItemRemoveEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 12/14/22.
//
// References:
// - Codable conformance to NSManagedObject: https://gist.github.com/Akhu/5ea1ecbd652fb269f7c4e7db27bc79cc
//

import Foundation
import CoreData

@objc(ESLaunchItemRemoveEvent)
public class ESLaunchItemRemoveEvent: NSManagedObject, Identifiable {
    @NSManaged public var instigator: ESProcess?
    @NSManaged public var instigator_token: ESAuditToken?
    
    @NSManaged public var app: ESProcess?
    @NSManaged public var app_token: ESAuditToken?
    
    @NSManaged public var item: ESLaunchItem

    enum CodingKeys: CodingKey {
        case instigator
        case app
        case item
        case instigator_token, app_token
    }
    
    // MARK: - Custom Core Data initilizer for ESLaunchItemRemoveEvent
    convenience init(from event: LaunchItemRemoveEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        let version: Int = message.version
        
        self.instigator = event.instigator.map {
            ESProcess(from: $0, version: version, insertIntoManagedObjectContext: context)
        }
        self.app = event.app.map { ESProcess(from: $0, version: version, insertIntoManagedObjectContext: context) }
        
        item = ESLaunchItem(from: event.item, insertIntoManagedObjectContext: context)
        
        if let instigator_token = event.instigator_token {
            self.instigator_token = ESAuditToken(from: instigator_token, insertIntoManagedObjectContext: context)
        }
        
        self.app_token = event.app_token.map { ESAuditToken(from: $0, insertIntoManagedObjectContext: context) }
    }
}

// MARK: - Encodable conformance
extension ESLaunchItemRemoveEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(instigator, forKey: .instigator)
        try container.encode(app, forKey: .app)
        try container.encode(item, forKey: .item)
        
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
