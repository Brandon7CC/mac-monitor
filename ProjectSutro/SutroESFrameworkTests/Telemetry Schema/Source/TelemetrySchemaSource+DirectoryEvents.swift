//
//  TelemetrySchemaSource+DirectoryEvents.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - Open Directory events
extension TelemetrySchemaSource {
    /// The Open Directory events Mac Monitor records.
    static var directoryEvents: [SchemaEvent] {
        let member = { (type: es_event_type_t, description: String) in
            directory(type, description, [
                eslogger("group_name", .string),
                eslogger("member", .nullable(.ref("od_member")),
                         "null in a record from Mac Monitor before 2.2.0 whose member's type it didn't know."),
                addition("member_string", .nullable(.string), "The name of the member's type."),
            ])
        }
        return [
            directory(ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER, "A user created: es_event_od_create_user_t.", [
                eslogger("user_name", .string),
            ]),
            directory(ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP, "A group created: es_event_od_create_group_t.", [
                eslogger("group_name", .string),
            ]),
            member(ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD, "A member added to a group: es_event_od_group_add_t."),
            member(ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE, "A member removed from a group: es_event_od_group_remove_t."),
            directory(ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD,
                      "An account's password changed: es_event_od_modify_password_t.", [
                eslogger("account_type", .nullable(.integer), "The es_od_account_type_t."),
                eslogger("account_name", .string),
                addition("account_type_string", .nullable(.string), "The name of `account_type`."),
            ]),
            directory(ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD,
                      "A value added to a record's attribute: es_event_od_attribute_value_add_t.", [
                eslogger("record_type", .nullable(.integer), "The es_od_record_type_t."),
                eslogger("record_name", .string),
                eslogger("attribute_name", .string),
                eslogger("attribute_value", .string),
                addition("record_type_string", .nullable(.string), "The name of `record_type`."),
            ]),
        ]
    }
    
    /// An Open Directory event: the keys every one has, and its own.
    ///
    /// - Parameters:
    ///   - type: The event's type.
    ///   - description: What the event is.
    ///   - keys: The event's own keys.
    /// - Returns: The event.
    private static func directory(_ type: es_event_type_t, _ description: String, _ keys: [SchemaKey]) -> SchemaEvent {
        event(type, description, odCommon + keys)
    }
    
    /// The keys every Open Directory event has: eslogger's, then Mac Monitor's.
    private static var odCommon: [SchemaKey] {
        let instigator = "The instigator's %@, from `instigator` (or `instigator_token`); null when neither is known."
        return [
            eslogger("instigator", .nullable(.ref("process"))),
            eslogger("error_code", .integer, "0 for success, otherwise an error from odconstants.h."),
            eslogger("node_name", .string),
            eslogger("db_path", .nullable(.string)),
            eslogger("instigator_token", .nullable(.ref("audit_token")), "null before message version 8."),
            addition("error_code_human", .string, "The name and description of `error_code`."),
            addition("instigator_process_name", .nullable(.string), String(format: instigator, "executable's name")),
            addition("instigator_process_path", .nullable(.string), String(format: instigator, "executable's path")),
            addition("instigator_process_signing_id", .nullable(.string), String(format: instigator, "signing ID")),
            addition("instigator_process_audit_token", .nullable(.string),
                     String(format: instigator, "audit token as one line of text")),
        ]
    }
}
