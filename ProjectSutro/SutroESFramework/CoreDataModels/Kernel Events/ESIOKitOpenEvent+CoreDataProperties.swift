//
//  ESIOKitOpenEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//
//

import Foundation
import CoreData


extension ESIOKitOpenEvent {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESIOKitOpenEvent> {
        return NSFetchRequest<ESIOKitOpenEvent>(entityName: "ESIOKitOpenEvent")
    }

    @NSManaged public var id: UUID
    @NSManaged public var user_client_class: String
    @NSManaged public var user_client_type: Int64
    /// Message version 10 and later (`nil` before it): a `uint64_t`, kept by bit pattern. Read it as
    /// ``parentRegistryID``.
    @NSManaged public var parent_registry_id: NSNumber?
    @NSManaged public var parent_path: String?

}

extension ESIOKitOpenEvent : Identifiable {

}
