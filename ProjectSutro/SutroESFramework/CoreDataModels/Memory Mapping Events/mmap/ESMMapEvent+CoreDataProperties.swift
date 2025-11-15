//
//  ESMMapEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData


extension ESMMapEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESMMapEvent> {
        return NSFetchRequest<ESMMapEvent>(entityName: "ESMMapEvent")
    }

    @NSManaged public var id: UUID?
    @NSManaged public var protection: Int32
    @NSManaged public var max_protection: Int32
    @NSManaged public var flags: Int32
    @NSManaged public var file_pos: Int64
    @NSManaged public var source: ESFile

}

extension ESMMapEvent : Identifiable {

}
