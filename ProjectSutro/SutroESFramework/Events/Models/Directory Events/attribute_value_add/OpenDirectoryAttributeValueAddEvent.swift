//
//  OpenDirectoryAttributeValueAddEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 6/28/23.
//
// ES documentation: `es_event_od_attribute_value_add_t`
/**
 * @brief Notification that an attribute value was added to a record.
 *
 * @field instigator       Process that instigated operation (XPC caller).
 * @field error_code       0 indicates the operation succeeded.
 *                         Values inidicating specific failure reasons are defined in odconstants.h.
 * @field record_type      The type of the record to which the attribute value was added.
 * @field record_name      The name of the record to which the attribute value was added.
 * @field attribute_name   The name of the attribute to which the value was added.
 * @field attribute_value  The value that was added.
 * @field node_name        OD node being mutated.
 *                         Typically one of "/Local/Default", "/LDAPv3/<server>" or
 *                         "/Active Directory/<domain>".
 * @field db_path          Optional.  If node_name is "/Local/Default", this is
 *                         the path of the database against which OD is
 *                         authenticating.
 *
 * @note This event type does not support caching (notify-only).
 * @note Attributes conceptually have the type `Map String (Set String)`.
 *       Each OD record has a Map of attribute name to Set of attribute value.
 *       When an attribute value is added, it is inserted into the set of values for that name.
 */

import Foundation


/// Models an `ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD`: a value was added to an Open Directory record's attribute.
public struct OpenDirectoryAttributeValueAddEvent: Identifiable, Codable, Hashable, OpenDirectoryEvent {
    public var id: UUID = UUID()
    /// The process that instigated the operation (the XPC caller), or `nil` when Endpoint Security leaves it out.
    public var instigator: Process?
    /// The instigator's audit token: message version 8 and later.
    public var instigator_token: AuditToken?
    /// Error codes defined in: `odconstants.h`. An error code of 0 indicates success.
    public var error_code: Int = 0
    /// The record's type, an `es_od_record_type_t`: a user (0) or a group (1). `nil` only for an event recorded
    /// before 2.2.0 whose type Mac Monitor didn't know.
    public var record_type: Int?
    public var record_name: String?
    public var attribute_name: String?
    public var attribute_value: String?
    public var node_name: String?
    public var db_path: String?
    
    /// Mac Monitor enrichment: the error's description, the name of the record's type (written in place of
    /// `record_type` before 2.2.0), and the instigator's name, path, audit token and signing ID.
    public var error_code_human, record_type_string: String?
    public var instigator_process_name, instigator_process_path: String?
    public var instigator_process_audit_token, instigator_process_signing_id: String?
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: OpenDirectoryAttributeValueAddEvent, rhs: OpenDirectoryAttributeValueAddEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    /// Record the event of a message from Endpoint Security.
    ///
    /// - Parameter rawMessage: The message.
    init(from rawMessage: UnsafePointer<es_message_t>) {
        let event = rawMessage.pointee.event.od_attribute_value_add
        readCommonFields(from: event, version: Int(rawMessage.pointee.version))
        self.record_type = Int(event.pointee.record_type.rawValue)
        self.record_name = event.pointee.record_name.string ?? ""
        self.attribute_name = event.pointee.attribute_name.string ?? ""
        self.attribute_value = event.pointee.attribute_value.string ?? ""
        enrich()
    }
    
    /// Read the event from eslogger's JSON, an export, or the Security Extension, including those before
    /// 2.2.0, which wrote the name of the record's type as `record_type`.
    ///
    /// - Parameter decoder: The event's decoder.
    /// - Throws: The error decoding a field.
    public init(from decoder: Decoder) throws {
        try decodeCommonFields(from: decoder)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        (record_type, record_type_string) = try container.decodeODEnum(
            .record_type, name: .record_type_string, names: .recordType)
        record_name = try container.decodeIfPresent(String.self, forKey: .record_name)
        attribute_name = try container.decodeIfPresent(String.self, forKey: .attribute_name)
        attribute_value = try container.decodeIfPresent(String.self, forKey: .attribute_value)
    }
}


// MARK: - Mac Monitor enrichment
extension OpenDirectoryAttributeValueAddEvent: ESEnrichable {
    /// Derive the error code's description, the name of the record's type, and the instigator's fields.
    public mutating func enrich() {
        enrichCommonFields()
        record_type_string = record_type.map(ODEnumNames.recordType.name(of:)) ?? record_type_string
    }
}
