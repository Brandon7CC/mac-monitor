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
public class ESODCreateGroupEvent: ESODEvent {
    enum CodingKeys: CodingKey {
        case group_name
    }
    
    /// Store an event.
    ///
    /// - Parameters:
    ///   - message: The event's message.
    ///   - context: The context to insert into.
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: OpenDirectoryCreateGroupEvent = message.event.od_create_group!
        let description = NSEntityDescription.entity(forEntityName: "ESODCreateGroupEvent", in: context)!
        self.init(entity: description, insertInto: context)
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
