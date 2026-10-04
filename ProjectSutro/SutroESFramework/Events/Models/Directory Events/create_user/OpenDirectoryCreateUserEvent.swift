//
//  OpenDirectoryCreateUserEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//
//  @discussion macOS 14 Sonoma+
//

import Foundation


/// Models a `ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER` which describes a user account being added to an Open Directory service.
///
/// Examples of Open Directory implementations include: Active Directory (Windows) and OpenLDAP (an open-source directory service)
/// https://developer.apple.com/documentation/endpointsecurity/3228936-es_events_t/4161233-od_create_user
public struct OpenDirectoryCreateUserEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID()
    
    ///  Fields describing the process which instigated the operation. In some cases, this may be different from the `initiating_process`.
    ///  Described as the XPC caller.,
    public var instigator_process_name, instigator_process_path, instigator_process_audit_token, instigator_process_signing_id: String?
    /// The name of the user account that was created.
    public var user_name: String?
    /// The Open Directory service / node the account is being created in
    /// Example: `/Active Directory/<domain>`
    public var node_name: String?
    /// If the node exists at a local path like `/Local/Default` this field will be populated
    public var db_path: String?
    /// Error codes defined in: `odconstants.h`. An error code of 0 indicates success.
    public var error_code: Int
    /// Decoded OD error code from `odconstants.h`.
    public var error_code_human: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: OpenDirectoryCreateUserEvent, rhs: OpenDirectoryCreateUserEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let odUserCreatedEvent: es_event_od_create_user_t = rawMessage.pointee.event.od_create_user.pointee
        let instigatorProcess: es_process_t = odUserCreatedEvent.instigator!.pointee
        
        // @MARK: Instigator proc
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
        
        // MARK: Open Directory User Created Specifics
        self.error_code = Int(odUserCreatedEvent.error_code)
    
        self.user_name = ""
        if odUserCreatedEvent.user_name.length > 0 {
            self.user_name = String(cString: odUserCreatedEvent.user_name.data)
        }
        
        self.node_name = ""
        if odUserCreatedEvent.node_name.length > 0 {
            self.node_name = String(cString: odUserCreatedEvent.node_name.data)
        }
        
        self.db_path = ""
        if odUserCreatedEvent.db_path.length > 0 {
            self.db_path = String(cString: odUserCreatedEvent.db_path.data)
        }
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryCreateUserEvent: ESEnrichable {
    /// Derive the error code's description.
    public mutating func enrich() {
        error_code_human = decodeODErrorCode(error_code)
    }
}
