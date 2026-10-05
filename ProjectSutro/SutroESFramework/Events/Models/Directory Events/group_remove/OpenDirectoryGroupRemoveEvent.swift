//
//  OpenDirectoryRemoveGroupEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/13/23.
//
// MARK: ES documentation reference `es_event_od_group_remove_t`
/**
 * @brief Notification that a member was removed from a group.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field group_name   The group from which the member was removed.
 * @field member       The identity of the member removed.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note This event does not indicate that a member was actually removed.
 *       For example when removing a user from a group they are not a member of.
 */

import Foundation


/// Models an `ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE`: a member was removed from an Open Directory group.
public struct OpenDirectoryGroupRemoveEvent: Identifiable, Codable, Hashable, OpenDirectoryGroupMemberEvent {
    public var id: UUID = UUID.buffered()
    /// The process that instigated the operation (the XPC caller), or `nil` when Endpoint Security leaves it out.
    public var instigator: Process?
    /// The instigator's audit token: message version 8 and later.
    public var instigator_token: AuditToken?
    /// Error codes defined in: `odconstants.h`. An error code of 0 indicates success.
    public var error_code: Int = 0
    public var group_name: String?
    /// The member removed, as eslogger writes it.
    public var member: OpenDirectoryMember?
    public var node_name: String?
    public var db_path: String?
    
    /// Mac Monitor enrichment: the error's description, the name of the member's type (written in place of `member`
    /// before 2.2.0), and the instigator's name, path, audit token and signing ID.
    public var error_code_human, member_string: String?
    public var instigator_process_name, instigator_process_path: String?
    public var instigator_process_audit_token, instigator_process_signing_id: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: OpenDirectoryGroupRemoveEvent, rhs: OpenDirectoryGroupRemoveEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter rawMessage: The message.
    init(from rawMessage: UnsafePointer<es_message_t>) {
        read(from: rawMessage.pointee.event.od_group_remove, version: Int(rawMessage.pointee.version))
    }
    
    /// Read the event from eslogger's JSON, an export, or the Security Extension, including those before
    /// 2.2.0, which wrote the name of the member's type as `member`.
    ///
    /// - Parameter decoder: The event's decoder.
    /// - Throws: The error decoding a field.
    public init(from decoder: Decoder) throws {
        try decodeGroupMember(from: decoder)
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryGroupRemoveEvent: ESEnrichable {
    /// Derive the error code's description, the name of the member's type, and the instigator's fields.
    public mutating func enrich() {
        enrichGroupMember()
    }
}
