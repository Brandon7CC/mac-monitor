//
//  ESODGroupMemberEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import CoreData


/// The fields a stored `od_group_add` or `od_group_remove` event has besides ``ESODEvent``'s: the group and its member
/// (an abstract entity: each of the two event types is a sub-entity).
@objc(ESODGroupMemberEvent)
public class ESODGroupMemberEvent: ESODEvent {
    /// Store the fields every Open Directory event has, then the group and its member.
    ///
    /// - Parameters:
    ///   - event: The event.
    ///   - version: The message's version.
    ///   - context: The context this object is in.
    func store(groupMember event: some OpenDirectoryGroupMemberEvent, version: Int,
               in context: NSManagedObjectContext) {
        store(event, version: version, in: context)
        group_name = event.group_name
        member_type = event.member.map { NSNumber(value: $0.member_type) }
        member_value = event.member?.member_value
        member_string = event.member_string
    }
    
    /// The member, as eslogger writes it: `nil` only for an event recorded before 2.2.0 whose member's type Mac Monitor
    /// didn't know.
    public var member: OpenDirectoryMember? {
        member_type.map { OpenDirectoryMember(member_type: $0.intValue, member_value: member_value) }
    }
}

// MARK: - Encodable conformance
extension ESODGroupMemberEvent: Encodable {
    /// Encode the event: eslogger's fields, then Mac Monitor's.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The error encoding a field.
    public func encode(to encoder: Encoder) throws {
        try encodeCommonFields(to: encoder)
        var container = encoder.container(keyedBy: ODGroupMemberKeys.self)
        try container.encode(group_name, forKey: .group_name)
        try container.encode(member, forKey: .member)
        try container.encode(member_string, forKey: .member_string)
    }
}
