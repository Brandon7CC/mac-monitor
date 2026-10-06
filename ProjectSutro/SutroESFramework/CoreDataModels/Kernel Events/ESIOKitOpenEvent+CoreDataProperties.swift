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
    /// Whether the message's version has the parent's fields: 10 (macOS 26) and later. The export writes both keys
    /// then, `null` for one the record didn't have.
    @NSManaged public var has_parent_fields: Bool
    /// Message version 10 and later (`nil` before it, or when the record had none): a `uint64_t`, kept by bit pattern.
    /// Read it as ``parentRegistryID``.
    @NSManaged public var parent_registry_id: NSNumber?
    @NSManaged public var parent_path: String?

}

extension ESIOKitOpenEvent : Identifiable {

}
