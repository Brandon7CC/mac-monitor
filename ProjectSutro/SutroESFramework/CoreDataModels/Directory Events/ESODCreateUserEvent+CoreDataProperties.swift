//
//  ESODCreateUserEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//
//

import Foundation
import CoreData


extension ESODCreateUserEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESODCreateUserEvent> {
        return NSFetchRequest<ESODCreateUserEvent>(entityName: "ESODCreateUserEvent")
    }

    @NSManaged public var user_name: String?
}

extension ESODCreateUserEvent : Identifiable {

}
