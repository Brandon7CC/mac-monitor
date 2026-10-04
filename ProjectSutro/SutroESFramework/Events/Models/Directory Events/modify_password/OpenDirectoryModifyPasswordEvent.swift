//
//  OpenDirectoryModifyPasswordEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//

import Foundation


public struct OpenDirectoryModifyPasswordEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    public var instigator_process_name, instigator_process_path, instigator_process_audit_token, instigator_process_signing_id: String?
    public var account_type: String?
    public var account_name: String?
    public var node_name: String?
    public var db_path: String?
    /// Error codes defined in: `odconstants.h`. An error code of 0 indicates success.
    public var error_code: Int
    /// Decoded OD error code from `odconstants.h`.
    public var error_code_human: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: OpenDirectoryModifyPasswordEvent, rhs: OpenDirectoryModifyPasswordEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let odModifyPasswordEvent: es_event_od_modify_password_t = rawMessage.pointee.event.od_modify_password.pointee
        let instigatorProcess: es_process_t = odModifyPasswordEvent.instigator!.pointee
        
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
        
        self.error_code = Int(odModifyPasswordEvent.error_code)
        
        switch odModifyPasswordEvent.account_type.rawValue {
        case ES_OD_ACCOUNT_TYPE_USER.rawValue:
            self.account_type = "ES_OD_ACCOUNT_TYPE_USER"
        case ES_OD_ACCOUNT_TYPE_COMPUTER.rawValue:
            self.account_type = "ES_OD_ACCOUNT_TYPE_COMPUTER"
        default:
            self.account_type = "UNKNOWN_ACCOUNT_TYPE"
        }
        
        self.account_name = ""
        if odModifyPasswordEvent.account_name.length > 0 {
            self.account_name = String(cString: odModifyPasswordEvent.account_name.data)
        }
        
        self.node_name = ""
        if odModifyPasswordEvent.node_name.length > 0 {
            self.node_name = String(cString: odModifyPasswordEvent.node_name.data)
        }
        
        self.db_path = ""
        if odModifyPasswordEvent.db_path.length > 0 {
            self.db_path = String(cString: odModifyPasswordEvent.db_path.data)
        }
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryModifyPasswordEvent: ESEnrichable {
    /// Derive the error code's description.
    public mutating func enrich() {
        error_code_human = decodeODErrorCode(error_code)
    }
}
