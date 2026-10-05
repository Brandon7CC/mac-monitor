//
//  ESODModifyPasswordEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//
//

import Foundation
import CoreData


/// A stored `od_modify_password` event.
@objc(ESODModifyPasswordEvent)
public class ESODModifyPasswordEvent: ESODEvent {
    enum CodingKeys: CodingKey {
        case account_type, account_name, account_type_string
    }
    
    /// Store an event.
    ///
    /// - Parameters:
    ///   - message: The event's message.
    ///   - context: The context to insert into.
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let event: OpenDirectoryModifyPasswordEvent = message.event.od_modify_password!
        let description = NSEntityDescription.entity(forEntityName: "ESODModifyPasswordEvent", in: context)!
        self.init(entity: description, insertInto: context)
        store(event, version: message.version, in: context)
        account_type = event.account_type.map { NSNumber(value: $0) }
        account_name = event.account_name
        account_type_string = event.account_type_string
    }
}

// MARK: - Encodable conformance
extension ESODModifyPasswordEvent: Encodable {
    /// Encode the event: eslogger's fields, then Mac Monitor's.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The error encoding a field.
    public func encode(to encoder: Encoder) throws {
        try encodeCommonFields(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(account_type?.intValue, forKey: .account_type)
        try container.encode(account_name, forKey: .account_name)
        try container.encode(account_type_string, forKey: .account_type_string)
    }
}
