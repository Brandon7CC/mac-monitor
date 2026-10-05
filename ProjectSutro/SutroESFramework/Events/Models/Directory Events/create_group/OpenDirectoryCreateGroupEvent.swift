//
//  OpenDirectoryCreateGroupEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/28/23.
//
// ES documentation: `es_event_od_create_group_t`
/**
 * @brief Notification that a group was created.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field error_code   0 indicates the operation succeeded.
 *                     Values inidicating specific failure reasons are defined in odconstants.h.
 * @field user_name    The name of the group that was created.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 */

import Foundation


/// Models an `ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP`: a group was created in an Open Directory node.
public struct OpenDirectoryCreateGroupEvent: Identifiable, Codable, Hashable, OpenDirectoryEvent {
    public var id: UUID = UUID()
    /// The process that instigated the operation (the XPC caller), or `nil` when Endpoint Security leaves it out.
    public var instigator: Process?
    /// The instigator's audit token: message version 8 and later.
    public var instigator_token: AuditToken?
    public var group_name: String?
    public var node_name: String?
    public var db_path: String?
    /// Error codes defined in: `odconstants.h`. An error code of 0 indicates success.
    public var error_code: Int = 0
    
    /// Mac Monitor enrichment: the error's description, and the instigator's name, path, audit token and signing ID.
    public var error_code_human: String?
    public var instigator_process_name, instigator_process_path: String?
    public var instigator_process_audit_token, instigator_process_signing_id: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: OpenDirectoryCreateGroupEvent, rhs: OpenDirectoryCreateGroupEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter rawMessage: The message.
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event = rawMessage.pointee.event.od_create_group
        readCommonFields(from: event, version: Int(rawMessage.pointee.version))
        self.group_name = event.pointee.group_name.string ?? ""
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryCreateGroupEvent: ESEnrichable {
    /// Derive the error code's description and the instigator's fields.
    public mutating func enrich() {
        enrichCommonFields()
    }
}
