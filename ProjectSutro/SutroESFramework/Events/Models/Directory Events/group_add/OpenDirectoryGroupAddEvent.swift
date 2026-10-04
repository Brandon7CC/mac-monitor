//
//  OpenDirectoryAddGroupEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/13/23.
//
// MARK: ES Documentation Reference `es_event_od_group_add_t`
/**
 * @brief Notification that a member was added to a group.
 *
 * @field instigator   Process that instigated operation (XPC caller).
 * @field group_name   The group to which the member was added.
 * @field member       The identity of the member added.
 * @field node_name    OD node being mutated.
 *                     Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                     "/Active Directory/<domain>".
 * @field db_path      Optional.  If node_name is "/Local/Default", this is
 *                     the path of the database against which OD is
 *                     authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note This event does not indicate that a member was actually added.
 *       For example when adding a user to a group they are already a member of.
 */

import Foundation


public struct OpenDirectoryGroupAddEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    public var instigator_process_name, instigator_process_path, instigator_process_audit_token, instigator_process_signing_id: String?
    public var group_name: String?
    public var member: String?
    public var node_name: String?
    public var db_path: String?
    /// Error codes defined in: `odconstants.h`. An error code of 0 indicates success.
    public var error_code: Int
    /// Decoded OD error code from `odconstants.h`.
    public var error_code_human: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: OpenDirectoryGroupAddEvent, rhs: OpenDirectoryGroupAddEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let odGroupAddEvent: es_event_od_group_add_t = rawMessage.pointee.event.od_group_add.pointee
        let instigatorProcess: es_process_t = odGroupAddEvent.instigator!.pointee
        
        self.instigator_process_name = ""
        if instigatorProcess.executable.pointee.path.length > 0 {
            self.instigator_process_name = URL(filePath: String(cString: instigatorProcess.executable.pointee.path.data)).lastPathComponent
        }
        
        self.instigator_process_path = ""
        if instigatorProcess.executable.pointee.path.length > 0 {
            self.instigator_process_path = String(cString: instigatorProcess.executable.pointee.path.data)
        }
        
        self.instigator_process_signing_id = ""
        if instigatorProcess.signing_id.length > 0 {
            self.instigator_process_signing_id = String(cString: instigatorProcess.signing_id.data)
        }
        
        self.instigator_process_audit_token = ""
        self.instigator_process_audit_token =  instigatorProcess.audit_token
            .toString()
        
        self.error_code = Int(odGroupAddEvent.error_code)
    
        self.group_name = ""
        if odGroupAddEvent.group_name.length > 0 {
            self.group_name = String(cString: odGroupAddEvent.group_name.data)
        }
        
        self.member = odMemberTypeName(odGroupAddEvent.member.pointee.member_type)
        
        self.node_name = ""
        if odGroupAddEvent.node_name.length > 0 {
            self.node_name = String(cString: odGroupAddEvent.node_name.data)
        }
        
        self.db_path = ""
        if odGroupAddEvent.db_path.length > 0 {
            self.db_path = String(cString: odGroupAddEvent.db_path.data)
        }
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryGroupAddEvent: ESEnrichable {
    /// Derive the error code's description.
    public mutating func enrich() {
        error_code_human = decodeODErrorCode(error_code)
    }
}
