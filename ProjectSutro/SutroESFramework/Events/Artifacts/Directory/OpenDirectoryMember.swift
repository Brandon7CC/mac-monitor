//
//  OpenDirectoryMember.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Group member
/// The member an `od_group_add` or `od_group_remove` event names (`es_od_member_id_t`), as eslogger writes it:
/// `{"member_type": 0, "member_value": "jappleseed"}`.
public struct OpenDirectoryMember: Codable, Hashable {
    /// The member's type, an `es_od_member_type_t`: a user's name (0), a user's UUID (1) or a group's UUID (2).
    public var member_type: Int
    /// The user's name, or the user's or group's UUID in uppercase. `nil` for a type the SDK doesn't define (eslogger
    /// writes no event then), and for a member recorded before 2.2.0, which kept only its type.
    public var member_value: String?
    
    /// A member from its fields.
    ///
    /// - Parameters:
    ///   - member_type: The member's `es_od_member_type_t`.
    ///   - member_value: The member's name or UUID.
    init(member_type: Int, member_value: String?) {
        self.member_type = member_type
        self.member_value = member_value
    }
    
    /// A member as Endpoint Security names it.
    ///
    /// - Parameter member: The event's `member`. Its `member_value` is read as the arm `member_type` names: `name`
    ///   for a user's name, and `uuid` for a user's or group's UUID.
    init(from member: es_od_member_id_t) {
        member_type = Int(member.member_type.rawValue)
        switch member.member_type {
        case ES_OD_MEMBER_TYPE_USER_NAME:
            member_value = member.member_value.name.string
        case ES_OD_MEMBER_TYPE_USER_UUID, ES_OD_MEMBER_TYPE_GROUP_UUID:
            member_value = UUID(uuid: member.member_value.uuid).uuidString
        default:
            member_value = nil
        }
    }
    
    /// Write both fields: `member_value` is `null` when it's `nil`, as eslogger writes every key it has.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The error encoding a field.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(member_type, forKey: .member_type)
        try container.encode(member_value, forKey: .member_value)
    }
}
