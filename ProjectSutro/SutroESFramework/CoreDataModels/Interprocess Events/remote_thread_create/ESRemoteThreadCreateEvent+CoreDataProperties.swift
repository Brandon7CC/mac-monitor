//
//  ESRemoteThreadCreateEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//
//

import Foundation
import CoreData


extension ESRemoteThreadCreateEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESRemoteThreadCreateEvent> {
        return NSFetchRequest<ESRemoteThreadCreateEvent>(entityName: "ESRemoteThreadCreateEvent")
    }

    @NSManaged public var id: UUID
    @NSManaged public var target: ESProcess
    /// The thread state's `flavor`, or `nil` when the event has no thread state (`thread_create`).
    @NSManaged public var thread_state_flavor: NSNumber?
    /// The thread state's bytes in base64 (``ThreadState/state_base64``).
    @NSManaged public var thread_state_base64: String?
    /// Mac Monitor enrichment: the name of the thread state's flavor.
    @NSManaged public var thread_state_string: String?

}

extension ESRemoteThreadCreateEvent : Identifiable {

}
