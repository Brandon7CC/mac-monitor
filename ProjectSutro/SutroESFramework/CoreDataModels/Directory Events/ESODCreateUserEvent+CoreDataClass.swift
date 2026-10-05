//
//  ESODCreateUserEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//
//

import Foundation
import CoreData


/// Models an [`es_event_od_create_user_t`](https://developer.apple.com/documentation/endpointsecurity/3228936-es_events_t/4161233-od_create_user)  which
/// is emitted when a user is added to an Open Directory node.
///
///
@objc(ESODCreateUserEvent)
public class ESODCreateUserEvent: ESODEvent {
    enum CodingKeys: CodingKey {
        case user_name
    }
    
    /// Store an event.
    ///
    /// - Parameters:
    ///   - message: The event's message.
    ///   - context: The context to insert into.
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: OpenDirectoryCreateUserEvent = message.event.od_create_user!
        let description = NSEntityDescription.entity(forEntityName: "ESODCreateUserEvent", in: context)!
        self.init(entity: description, insertInto: context)
        store(event, version: message.version, in: context)
        user_name = event.user_name
    }
}

// MARK: - Encodable conformance
extension ESODCreateUserEvent: Encodable {
    /// Encode the event: eslogger's fields, then Mac Monitor's.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The error encoding a field.
    public func encode(to encoder: Encoder) throws {
        try encodeCommonFields(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(user_name, forKey: .user_name)
    }
}
