//
//  ESODAttributeValueAddEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/28/23.
//
//

import Foundation
import CoreData


extension ESODAttributeValueAddEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESODAttributeValueAddEvent> {
        return NSFetchRequest<ESODAttributeValueAddEvent>(entityName: "ESODAttributeValueAddEvent")
    }

    @NSManaged public var record_type: NSNumber?
    @NSManaged public var record_name: String?
    @NSManaged public var attribute_name: String?
    @NSManaged public var attribute_value: String?
    @NSManaged public var record_type_string: String?
}

extension ESODAttributeValueAddEvent : Identifiable {

}
