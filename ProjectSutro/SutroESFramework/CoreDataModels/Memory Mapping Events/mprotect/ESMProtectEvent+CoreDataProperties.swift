//
//  ESMProtectEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/14/25.
//
//

import Foundation
import CoreData


extension ESMProtectEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESMProtectEvent> {
        return NSFetchRequest<ESMProtectEvent>(entityName: "ESMProtectEvent")
    }

    @NSManaged public var id: UUID?
    @NSManaged public var protection: Int32
    @NSManaged public var address: Int64
    @NSManaged public var size: Int64

}

extension ESMProtectEvent : Identifiable {

}
