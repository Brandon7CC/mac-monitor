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


public struct OpenDirectoryCreateGroupEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    public var instigator_process_name, instigator_process_path, instigator_process_audit_token, instigator_process_signing_id: String?
    public var group_name: String?
    public var node_name: String?
    public var db_path: String?
    /// Error codes defined in: `odconstants.h`. An error code of 0 indicates success.
    public var error_code: Int
    /// Decoded OD error code from `odconstants.h`.
    public var error_code_human: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: OpenDirectoryCreateGroupEvent, rhs: OpenDirectoryCreateGroupEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let odGroupCreatedEvent: es_event_od_create_group_t = rawMessage.pointee.event.od_create_group.pointee
        let instigatorProcess: es_process_t = odGroupCreatedEvent.instigator!.pointee
        
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
        self.instigator_process_audit_token = instigatorProcess.audit_token
            .toString()
        
        self.error_code = Int(odGroupCreatedEvent.error_code)
    
        self.group_name = ""
        if odGroupCreatedEvent.group_name.length > 0 {
            self.group_name = String(cString: odGroupCreatedEvent.group_name.data)
        }
        
        self.node_name = ""
        if odGroupCreatedEvent.node_name.length > 0 {
            self.node_name = String(cString: odGroupCreatedEvent.node_name.data)
        }
        
        self.db_path = ""
        if odGroupCreatedEvent.db_path.length > 0 {
            self.db_path = String(cString: odGroupCreatedEvent.db_path.data)
        }
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryCreateGroupEvent: ESEnrichable {
    /// Derive the error code's description.
    public mutating func enrich() {
        error_code_human = decodeODErrorCode(error_code)
    }
}
