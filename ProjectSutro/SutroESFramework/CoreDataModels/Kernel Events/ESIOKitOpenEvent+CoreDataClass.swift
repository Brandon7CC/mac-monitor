//
//  ESIOKitOpenEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//
//

import Foundation
import CoreData

@objc(ESIOKitOpenEvent)
public class ESIOKitOpenEvent: NSManagedObject, Identifiable {
    @NSManaged public var user_client_class: String
    @NSManaged public var user_client_type: Int64
    /// Whether the message's version has the parent's fields: 10 (macOS 26) and later. The export writes both keys
    /// then, `null` for one the record didn't have.
    @NSManaged public var has_parent_fields: Bool
    /// Message version 10 and later (`nil` before it, or when the record had none): a `uint64_t`, kept by bit pattern.
    /// Read it as ``parentRegistryID``.
    @NSManaged public var parent_registry_id: NSNumber?
    @NSManaged public var parent_path: String?
    /// The class of the service being opened, read from the IOKit registry at capture. `nil` before message version
    /// 10, when it couldn't be read, or when the record had none.
    @NSManaged public var parent_class: String?
    /// The bundle ID of the service's driver, read from the IOKit registry at capture. `nil` as ``parent_class`` is,
    /// or when the registry names none.
    @NSManaged public var driver_bundle_id: String?

    enum CodingKeys: CodingKey {
        case user_client_class
        case user_client_type
        case parent_registry_id
        case parent_path
        case parent_class
        case driver_bundle_id
    }

    // MARK: - Custom Core Data initilizer for ESIOKitOpenEvent
    convenience init(from event: IOKitOpenEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)

        self.user_client_type = event.user_client_type
        self.user_client_class = event.user_client_class

        /// Message version 10 and later: before it, Endpoint Security has no such fields and eslogger writes neither.
        if message.version >= 10 {
            self.has_parent_fields = true
            self.parent_registry_id = event.parent_registry_id.map { NSNumber(value: $0) }
            self.parent_path = event.parent_path
            self.parent_class = event.parent_class
            self.driver_bundle_id = event.driver_bundle_id
        }
    }

    /// The parent's IOKit registry ID, unsigned as Endpoint Security gives it, or `nil` before message version 10 or
    /// when the record had none.
    public var parentRegistryID: UInt64? {
        parent_registry_id.map { UInt64(bitPattern: $0.int64Value) }
    }
}

// MARK: - Mac Monitor enrichment
extension ESIOKitOpenEvent {
    /// The service being opened, by name: its class, else the last component of its path.
    public var serviceName: String? {
        Self.serviceName(className: parent_class, path: parent_path)
    }

    /// What opening the user client gives, from ``IOKitUserClients``, or `nil` for a class it doesn't have.
    public var userClientDescription: String? {
        IOKitUserClients.description(of: user_client_class)
    }

    /// A service's name: its class, else the last component of its registry path, which names the entry, so
    /// `IOService:/AppleARMPE/IOPMrootDomain` is `IOPMrootDomain`.
    ///
    /// - Parameters:
    ///   - className: The service's class, if it was read.
    ///   - path: The service's registry path, if Endpoint Security gave one.
    /// - Returns: The name, or `nil` when neither gives one.
    static func serviceName(className: String?, path: String?) -> String? {
        if let className, !className.isEmpty { return className }
        guard let component = path?.split(separator: "/").last.map(String.init),
              !component.isEmpty, !component.hasSuffix(":") else { return nil }
        return component
    }
}

// MARK: - Encodable conformance
extension ESIOKitOpenEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(user_client_type, forKey: .user_client_type)
        try container.encode(user_client_class, forKey: .user_client_class)

        /// Message version 10 (macOS 26) and later only, as eslogger writes them: both keys, or neither. A value the
        /// record didn't have is `null`, never made up.
        if has_parent_fields {
            try container.encode(parent_path, forKey: .parent_path)
            try container.encode(parentRegistryID, forKey: .parent_registry_id)
        }
        /// Always both keys: `null` before message version 10, when the registry couldn't be read, and in a record
        /// from eslogger or Mac Monitor before 3.1.0.
        try container.encode(parent_class, forKey: .parent_class)
        try container.encode(driver_bundle_id, forKey: .driver_bundle_id)
    }
}
