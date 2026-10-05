//
//  ESLaunchItemAddEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData


extension ESLaunchItemAddEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESLaunchItemAddEvent> {
        return NSFetchRequest<ESLaunchItemAddEvent>(entityName: "ESLaunchItemAddEvent")
    }

    @NSManaged public var id: UUID?
    
    @NSManaged public var instigator: ESProcess?
    @NSManaged public var instigator_token: ESAuditToken?
    
    @NSManaged public var app: ESProcess?
    @NSManaged public var app_token: ESAuditToken?
    
    @NSManaged public var item: ESLaunchItem
    @NSManaged public var executable_path: String?

}

extension ESLaunchItemAddEvent : Identifiable {

}
