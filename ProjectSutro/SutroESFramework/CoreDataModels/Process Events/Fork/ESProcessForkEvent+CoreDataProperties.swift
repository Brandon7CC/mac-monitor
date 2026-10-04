//
//  ESProcessForkEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData


extension ESProcessForkEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESProcessForkEvent> {
        return NSFetchRequest<ESProcessForkEvent>(entityName: "ESProcessForkEvent")
    }
    
    @NSManaged public var id: UUID?
    /// The child process. The row may be shared with the events the child goes on to cause.
    @NSManaged public var child: ESProcess
    /// The `id` ``child`` had in this event (and exports). A shared row keeps the `id` of the first event that stored it.
    @NSManaged public var child_id: UUID?

}

extension ESProcessForkEvent : Identifiable {

}
