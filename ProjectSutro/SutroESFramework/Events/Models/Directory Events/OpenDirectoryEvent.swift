//
//  OpenDirectoryEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Endpoint Security's Open Directory events
/// The fields every `es_event_od_*_t` that Mac Monitor records has: the process that instigated the operation (the
/// XPC caller) and the operation's result first, then the node it changed, the node's database, and the instigator's
/// audit token.
protocol ODEventFields {
    /// The instigator, or `NULL` when Endpoint Security leaves it out.
    var instigator: UnsafeMutablePointer<es_process_t>? { get }
    /// 0 for success, otherwise an error from `odconstants.h`.
    var error_code: Int32 { get }
    /// The node changed, such as `/Local/Default`.
    var node_name: es_string_token_t { get }
    /// Optional: the database of a local node.
    var db_path: es_string_token_t { get }
    /// The instigator's audit token. Message version 8 and later.
    var instigator_token: audit_token_t { get }
}

/// The fields of an `es_event_od_group_add_t` or `es_event_od_group_remove_t`.
protocol ODGroupMemberFields: ODEventFields {
    /// The group.
    var group_name: es_string_token_t { get }
    /// The member added or removed.
    var member: UnsafeMutablePointer<es_od_member_id_t> { get }
}

extension es_event_od_create_user_t: ODEventFields {}
extension es_event_od_create_group_t: ODEventFields {}
extension es_event_od_modify_password_t: ODEventFields {}
extension es_event_od_attribute_value_add_t: ODEventFields {}
extension es_event_od_group_add_t: ODGroupMemberFields {}
extension es_event_od_group_remove_t: ODGroupMemberFields {}


// MARK: - Mac Monitor's Open Directory events
/// The keys every Open Directory event has: eslogger's, then Mac Monitor's own.
enum ODEventKeys: String, CodingKey {
    case id, instigator, error_code, node_name, db_path, instigator_token
    case error_code_human, instigator_process_name, instigator_process_path, instigator_process_signing_id,
         instigator_process_audit_token
}

/// An Open Directory event as Mac Monitor records it: eslogger's fields, plus the error's description and the
/// instigator's name, path, signing ID and audit token, which Mac Monitor showed before it kept the instigator.
protocol OpenDirectoryEvent: ESEnrichable {
    var id: UUID { get set }
    /// The process that instigated the operation (the XPC caller), or `nil` when Endpoint Security leaves it out.
    var instigator: Process? { get set }
    /// The instigator's audit token: message version 8 and later.
    var instigator_token: AuditToken? { get set }
    /// 0 for success, otherwise an error from `odconstants.h`.
    var error_code: Int { get set }
    /// The node changed, such as `/Local/Default`, `/LDAPv3/<server>` or `/Active Directory/<domain>`.
    var node_name: String? { get set }
    /// The database of a `/Local/Default` node, or `nil`.
    var db_path: String? { get set }
    
    /// Mac Monitor enrichment: the error's name and description (``decodeODErrorCode(_:)``).
    var error_code_human: String? { get set }
    /// Mac Monitor enrichment: the instigator's executable's file name.
    var instigator_process_name: String? { get set }
    /// Mac Monitor enrichment: the instigator's executable's path.
    var instigator_process_path: String? { get set }
    /// Mac Monitor enrichment: the instigator's signing ID.
    var instigator_process_signing_id: String? { get set }
    /// Mac Monitor enrichment: the instigator's audit token, as `audit_token_t.toString()` writes it.
    var instigator_process_audit_token: String? { get set }
}

extension OpenDirectoryEvent {
    /// Read the fields every Open Directory event has.
    ///
    /// Each field is read through `event`, and `instigator_token` only from message version 8, so the event of an
    /// older message, which ends before it, isn't read past its end.
    ///
    /// - Parameters:
    ///   - event: The message's event.
    ///   - version: The message's version.
    mutating func readCommonFields(from event: UnsafeMutablePointer<some ODEventFields>, version: Int) {
        instigator = event.pointee.instigator.map { Process(from: $0.pointee, version: version) }
        error_code = Int(event.pointee.error_code)
        node_name = event.pointee.node_name.string ?? ""
        /// Optional: `nil` (eslogger's `null`) when the node has no local database.
        db_path = event.pointee.db_path.string
        if version >= 8 {
            instigator_token = AuditToken(from: event.pointee.instigator_token)
        }
    }
    
    /// Read the fields every Open Directory event has from JSON: eslogger's, an export's, or the Security
    /// Extension's (whose `id` is kept).
    ///
    /// - Parameter decoder: The event's decoder.
    /// - Throws: The error decoding a field.
    mutating func decodeCommonFields(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: ODEventKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        instigator = try container.decodeIfPresent(Process.self, forKey: .instigator)
        instigator_token = try container.decodeIfPresent(AuditToken.self, forKey: .instigator_token)
        error_code = try container.decodeIfPresent(Int.self, forKey: .error_code) ?? 0
        node_name = try container.decodeIfPresent(String.self, forKey: .node_name)
        db_path = try container.decodeIfPresent(String.self, forKey: .db_path)
        let text = { (key: ODEventKeys) in try container.decodeIfPresent(String.self, forKey: key) }
        error_code_human = try text(.error_code_human)
        instigator_process_name = try text(.instigator_process_name)
        instigator_process_path = try text(.instigator_process_path)
        instigator_process_signing_id = try text(.instigator_process_signing_id)
        instigator_process_audit_token = try text(.instigator_process_audit_token)
    }
    
    /// Derive the error's description, and the instigator's name, path, signing ID and audit token.
    ///
    /// Without the instigator's process, its audit token comes from `instigator_token`. An event recorded before
    /// 2.2.0 has neither (Mac Monitor didn't keep them), so the values it carries are kept.
    mutating func enrichCommonFields() {
        error_code_human = decodeODErrorCode(error_code)
        guard instigator != nil || instigator_token != nil else { return }
        instigator_process_path = instigator?.executable?.path
        instigator_process_name = instigator?.executable?.name
        instigator_process_signing_id = instigator?.signing_id
        instigator_process_audit_token = instigator?.audit_token?.toString() ?? instigator_token?.toString()
    }
}


// MARK: - Group members
/// The keys of an `od_group_add` or `od_group_remove` event besides ``ODEventKeys``.
enum ODGroupMemberKeys: String, CodingKey {
    case group_name, member, member_string
}

/// An `od_group_add` or `od_group_remove` event as Mac Monitor records it.
protocol OpenDirectoryGroupMemberEvent: OpenDirectoryEvent {
    /// The group.
    var group_name: String? { get set }
    /// The member added or removed: `nil` only for an event recorded before 2.2.0 whose member's type Mac Monitor
    /// didn't know.
    var member: OpenDirectoryMember? { get set }
    /// Mac Monitor enrichment: the name of the member's type (``ODEnumNames/memberType``).
    var member_string: String? { get set }
}

extension OpenDirectoryGroupMemberEvent {
    /// Read the event from Endpoint Security, and derive Mac Monitor's fields.
    ///
    /// - Parameters:
    ///   - event: The message's event.
    ///   - version: The message's version.
    mutating func read(from event: UnsafeMutablePointer<some ODGroupMemberFields>, version: Int) {
        readCommonFields(from: event, version: version)
        group_name = event.pointee.group_name.string ?? ""
        member = OpenDirectoryMember(from: event.pointee.member.pointee)
        enrichGroupMember()
    }
    
    /// Read the event from JSON.
    ///
    /// - Parameter decoder: The event's decoder.
    /// - Throws: The error decoding a field.
    mutating func decodeGroupMember(from decoder: Decoder) throws {
        try decodeCommonFields(from: decoder)
        let container = try decoder.container(keyedBy: ODGroupMemberKeys.self)
        group_name = try container.decodeIfPresent(String.self, forKey: .group_name)
        (member, member_string) = try container.decodeODMember(.member, name: .member_string)
    }
    
    /// Derive Mac Monitor's fields: the common ones, and the name of the member's type.
    mutating func enrichGroupMember() {
        enrichCommonFields()
        member_string = member.map { ODEnumNames.memberType.name(of: $0.member_type) } ?? member_string
    }
    
    /// The member for the event's summary: its name or UUID, or, for an event recorded before 2.2.0, the name of its
    /// type.
    var memberSummary: String {
        member?.member_value ?? member_string ?? ""
    }
}


// MARK: - Values Mac Monitor wrote differently before 2.2.0
extension KeyedDecodingContainer {
    /// An Open Directory enum's value and name: eslogger's number, or the name Mac Monitor wrote in its place before
    /// 2.2.0 (``ODEnumNames``).
    ///
    /// The number is tried first: ``TraceDecoder`` reads a number as a string of its digits too.
    ///
    /// - Parameters:
    ///   - key: The value's key, such as `record_type`.
    ///   - nameKey: The name's key, such as `record_type_string`.
    ///   - names: The enum's names.
    /// - Returns: The value, `nil` when it's missing or names no value; and the name, `nil` when it's missing.
    /// - Throws: The error decoding a value that's neither a number nor a string.
    func decodeODEnum(_ key: Key, name nameKey: Key, names: ODEnumNames) throws -> (Int?, String?) {
        if let value = try? decodeIfPresent(Int.self, forKey: key) {
            return (value, try decodeIfPresent(String.self, forKey: nameKey))
        }
        guard let name = try decodeIfPresent(String.self, forKey: key) else {
            return (nil, try decodeIfPresent(String.self, forKey: nameKey))
        }
        return (names.rawValue(of: name), name)
    }
    
    /// An `od_group_add` or `od_group_remove` event's member and the name of its type: eslogger's object, or the
    /// name Mac Monitor wrote in its place before 2.2.0.
    ///
    /// The name is tried first: ``TraceDecoder`` reads a string as an object holding it, whose fields it defaults.
    ///
    /// - Parameters:
    ///   - key: The member's key.
    ///   - nameKey: The name's key.
    /// - Returns: The member (without a value for a name, and `nil` for a name of no type), and the name.
    /// - Throws: The error decoding a member that's neither an object nor a string.
    func decodeODMember(_ key: Key, name nameKey: Key) throws -> (OpenDirectoryMember?, String?) {
        if let name = try? decodeIfPresent(String.self, forKey: key) {
            let type = ODEnumNames.memberType.rawValue(of: name)
            return (type.map { OpenDirectoryMember(member_type: $0, member_value: nil) }, name)
        }
        let member = try decodeIfPresent(OpenDirectoryMember.self, forKey: key)
        return (member, try decodeIfPresent(String.self, forKey: nameKey))
    }
}
