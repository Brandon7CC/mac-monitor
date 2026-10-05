//
//  ESODGroupRemoveEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/13/23.
//
//

import Foundation
import CoreData


extension ESODGroupRemoveEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESODGroupRemoveEvent> {
        return NSFetchRequest<ESODGroupRemoveEvent>(entityName: "ESODGroupRemoveEvent")
    }

}

extension ESODGroupRemoveEvent : Identifiable {

}
