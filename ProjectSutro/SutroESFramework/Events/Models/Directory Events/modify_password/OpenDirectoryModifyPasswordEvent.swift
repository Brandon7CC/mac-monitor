//
//  OpenDirectoryModifyPasswordEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/7/23.
//

import Foundation


/// Models an `ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD`: an account's password was changed in an Open Directory node.
public struct OpenDirectoryModifyPasswordEvent: Identifiable, Codable, Hashable, OpenDirectoryEvent {
    public var id: UUID = UUID()
    /// The process that instigated the operation (the XPC caller), or `nil` when Endpoint Security leaves it out.
    public var instigator: Process?
    /// The instigator's audit token: message version 8 and later.
    public var instigator_token: AuditToken?
    /// The account's type, an `es_od_account_type_t`: a user (0) or a computer (1). `nil` only for an event recorded
    /// before 2.2.0 whose type Mac Monitor didn't know.
    public var account_type: Int?
    public var account_name: String?
    public var node_name: String?
    public var db_path: String?
    /// Error codes defined in: `odconstants.h`. An error code of 0 indicates success.
    public var error_code: Int = 0
    
    /// Mac Monitor enrichment: the error's description, the name of the account's type (written in place of
    /// `account_type` before 2.2.0), and the instigator's name, path, audit token and signing ID.
    public var error_code_human, account_type_string: String?
    public var instigator_process_name, instigator_process_path: String?
    public var instigator_process_audit_token, instigator_process_signing_id: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: OpenDirectoryModifyPasswordEvent, rhs: OpenDirectoryModifyPasswordEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter rawMessage: The message.
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event = rawMessage.pointee.event.od_modify_password
        readCommonFields(from: event, version: Int(rawMessage.pointee.version))
        self.account_type = Int(event.pointee.account_type.rawValue)
        self.account_name = event.pointee.account_name.string ?? ""
        enrich()
    }
    
    /// Read the event from eslogger's JSON, an export, or the Security Extension, including those before
    /// 2.2.0, which wrote the name of the account's type as `account_type`.
    ///
    /// - Parameter decoder: The event's decoder.
    /// - Throws: The error decoding a field.
    public init(from decoder: Decoder) throws {
        try decodeCommonFields(from: decoder)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        (account_type, account_type_string) = try container.decodeODEnum(
            .account_type, name: .account_type_string, names: .accountType)
        account_name = try container.decodeIfPresent(String.self, forKey: .account_name)
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryModifyPasswordEvent: ESEnrichable {
    /// Derive the error code's description, the name of the account's type, and the instigator's fields.
    public mutating func enrich() {
        enrichCommonFields()
        account_type_string = account_type.map(ODEnumNames.accountType.name(of:)) ?? account_type_string
    }
}
