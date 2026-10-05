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
public struct OpenDirectoryCreateUserEvent: Identifiable, Codable, Hashable, OpenDirectoryEvent {
    public var id: UUID = UUID()
    
    /// The process that instigated the operation (the XPC caller), or `nil` when Endpoint Security leaves it out.
    public var instigator: Process?
    /// The instigator's audit token: message version 8 and later.
    public var instigator_token: AuditToken?
    /// The name of the user account that was created.
    public var user_name: String?
    /// The Open Directory service / node the account is being created in
    /// Example: `/Active Directory/<domain>`
    public var node_name: String?
    /// If the node exists at a local path like `/Local/Default` this field will be populated
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
    
    public static func == (lhs: OpenDirectoryCreateUserEvent, rhs: OpenDirectoryCreateUserEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter rawMessage: The message.
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event = rawMessage.pointee.event.od_create_user
        readCommonFields(from: event, version: Int(rawMessage.pointee.version))
        self.user_name = event.pointee.user_name.string ?? ""
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryCreateUserEvent: ESEnrichable {
    /// Derive the error code's description and the instigator's fields.
    public mutating func enrich() {
        enrichCommonFields()
    }
}
