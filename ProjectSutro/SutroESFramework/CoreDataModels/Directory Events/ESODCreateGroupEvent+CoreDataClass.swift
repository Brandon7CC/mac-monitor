//
//  ESODCreateGroupEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/28/23.
//
//

import Foundation
import CoreData


/// A stored `od_create_group` event.
@objc(ESODCreateGroupEvent)
public class ESODCreateGroupEvent: ESODEvent, Identifiable {
    @NSManaged public var group_name: String?

    enum CodingKeys: CodingKey {
        case group_name
    }
    
    /// Store an event.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - message: The event's message.
    ///   - context: The context to insert into.
    convenience init(from event: OpenDirectoryCreateGroupEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        store(event, version: message.version, in: context)
        group_name = event.group_name
    }
}

// MARK: - Encodable conformance
extension ESODCreateGroupEvent: Encodable {
    /// Encode the event: eslogger's fields, then Mac Monitor's.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The error encoding a field.
    public func encode(to encoder: Encoder) throws {
        try encodeCommonFields(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(group_name, forKey: .group_name)
    }
}
