//
//  ESODModifyPasswordEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//
//

import Foundation
import CoreData


extension ESODModifyPasswordEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESODModifyPasswordEvent> {
        return NSFetchRequest<ESODModifyPasswordEvent>(entityName: "ESODModifyPasswordEvent")
    }

    @NSManaged public var account_type: NSNumber?
    @NSManaged public var account_name: String?
    @NSManaged public var account_type_string: String?

}

extension ESODModifyPasswordEvent : Identifiable {

}
