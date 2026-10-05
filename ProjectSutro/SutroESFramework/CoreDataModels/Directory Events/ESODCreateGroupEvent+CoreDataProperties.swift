//
//  ESODCreateGroupEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/28/23.
//
//

import Foundation
import CoreData


extension ESODCreateGroupEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESODCreateGroupEvent> {
        return NSFetchRequest<ESODCreateGroupEvent>(entityName: "ESODCreateGroupEvent")
    }

    @NSManaged public var group_name: String?
}

extension ESODCreateGroupEvent : Identifiable {

}
