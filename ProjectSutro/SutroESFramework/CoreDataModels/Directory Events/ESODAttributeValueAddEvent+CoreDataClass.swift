//
//  ESODAttributeValueAddEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/28/23.
//
//

import Foundation
import CoreData


/// A stored `od_attribute_value_add` event.
@objc(ESODAttributeValueAddEvent)
public class ESODAttributeValueAddEvent: ESODEvent {
    enum CodingKeys: CodingKey {
        case record_type, record_name, attribute_name, attribute_value, record_type_string
    }
    
    /// Store an event.
    ///
    /// - Parameters:
    ///   - message: The event's message.
    ///   - context: The context to insert into.
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: OpenDirectoryAttributeValueAddEvent = message.event.od_attribute_value_add!
        let description = NSEntityDescription.entity(forEntityName: "ESODAttributeValueAddEvent", in: context)!
        self.init(entity: description, insertInto: context)
        store(event, version: message.version, in: context)
        record_type = event.record_type.map { NSNumber(value: $0) }
        record_name = event.record_name
        attribute_name = event.attribute_name
        attribute_value = event.attribute_value
        record_type_string = event.record_type_string
    }
}

// MARK: - Encodable conformance
extension ESODAttributeValueAddEvent: Encodable {
    /// Encode the event: eslogger's fields, then Mac Monitor's.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The error encoding a field.
    public func encode(to encoder: Encoder) throws {
        try encodeCommonFields(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(record_type?.intValue, forKey: .record_type)
        try container.encode(record_name, forKey: .record_name)
        try container.encode(attribute_name, forKey: .attribute_name)
        try container.encode(attribute_value, forKey: .attribute_value)
        try container.encode(record_type_string, forKey: .record_type_string)
    }
}
