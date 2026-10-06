//
//  TelemetrySchemaSource+SystemEvents.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import EndpointSecurity


// MARK: - System events
extension TelemetrySchemaSource {
    /// Login, OpenSSH, kernel, authorization, MDM, background task, XProtect, XPC, socket, TCC, Gatekeeper and
    /// pseudoterminal events.
    static var systemEvents: [SchemaEvent] {
        loginEvents + securityEvents + [
            event(ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN, "An IOKit device opened: es_event_iokit_open_t.", [
                eslogger("user_client_type", .integer),
                eslogger("user_client_class", .string),
                eslogger("parent_path", .nullable(.string),
                         "null when Endpoint Security gives none, or in a record from Mac Monitor before 2.2.0, which "
                         + "left out an empty one.",
                         absent: Absence("the message's version is before 10 (macOS 26)")),
                eslogger("parent_registry_id", .nullable(.integer),
                         "Unsigned. null in a record from Mac Monitor before 2.2.0, which left it out with an empty "
                         + "`parent_path`.",
                         absent: Absence("the message's version is before 10 (macOS 26)")),
            ]),
            event(ES_EVENT_TYPE_NOTIFY_XPC_CONNECT, "An XPC connection: es_event_xpc_connect_t.", [
                eslogger("service_name", .string),
            ] + named("service_domain_type", "The es_xpc_domain_type_t.")),
            event(ES_EVENT_TYPE_NOTIFY_UIPC_BIND, "A Unix domain socket bound: es_event_uipc_bind_t.", [
                eslogger("dir", .ref("file")), eslogger("filename", .string), eslogger("mode", .integer),
            ]),
            event(ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT, "A Unix domain socket connected: es_event_uipc_connect_t.", [
                eslogger("file", .ref("file")),
            ] + named("domain", "The socket's domain.") + named("type", "The socket's type.")
              + named("protocol", "The socket's protocol.")),
            event(ES_EVENT_TYPE_NOTIFY_PTY_GRANT, "A pseudoterminal granted: es_event_pty_grant_t.", [
                eslogger("dev", .integer),
            ]),
            launchItem(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
                       "A background task added: es_event_btm_launch_item_add_t.",
                       [eslogger("executable_path", .nullable(.string))]),
            launchItem(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
                       "A background task removed: es_event_btm_launch_item_remove_t.", []),
            event(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, "XProtect found malware: es_event_xp_malware_detected_t.", [
                eslogger("signature_version", .string), eslogger("malware_identifier", .string),
                eslogger("incident_identifier", .string), eslogger("detected_path", .string),
                eslogger("detected_executable", .nullable(.string), "null before message version 10."),
            ]),
            event(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED,
                  "XProtect remediated malware: es_event_xp_malware_remediated_t.", [
                eslogger("signature_version", .string), eslogger("malware_identifier", .string),
                eslogger("incident_identifier", .string), eslogger("action_type", .string),
                eslogger("success", .boolean), eslogger("result_description", .string),
                eslogger("remediated_path", .nullable(.string)),
                eslogger("remediated_process_audit_token", .nullable(.ref("audit_token"))),
            ]),
        ]
    }
    
    /// Login, login window and OpenSSH events.
    private static var loginEvents: [SchemaEvent] {
        let session = { (type: es_event_type_t, description: String) in
            event(type, description, [eslogger("username", .string),
                                      eslogger("graphical_session_id", .integer, "Unsigned.")])
        }
        return [
            event(ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, "A login with /usr/bin/login: es_event_login_login_t.", [
                eslogger("success", .boolean),
                eslogger("failure_message", .nullable(.string)),
                eslogger("username", .string),
                addition("has_uid", .boolean, "Whether `uid` is known."),
                eslogger("uid", .nullable(.integer)),
                addition("uid_human", .string, "The name of `uid`, or Unknown."),
            ]),
            session(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, "A login window login: es_event_lw_session_login_t."),
            session(ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, "A login window unlock: es_event_lw_session_unlock_t."),
            event(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, "An OpenSSH login: es_event_openssh_login_t.", [
                eslogger("success", .boolean),
            ] + named("result_type", "The es_openssh_login_result_type_t.")
              + named("source_address_type", "The es_address_type_t.") + [
                eslogger("source_address", .string),
                eslogger("username", .string),
                addition("has_uid", .boolean, "Whether `uid` is known."),
                eslogger("uid", .nullable(.integer), "Unsigned."),
            ]),
            event(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, "An OpenSSH logout: es_event_openssh_logout_t.",
                  named("source_address_type", "The es_address_type_t.") + [
                eslogger("source_address", .string),
                eslogger("username", .string),
                eslogger("uid", .integer, "Unsigned."),
            ]),
        ]
    }
    
    /// Authorization, MDM, TCC and Gatekeeper events.
    private static var securityEvents: [SchemaEvent] {
        let result = SchemaObject("A right's result: es_authorization_result_t.", [
            addition("id", .pattern(.uuid), "Mac Monitor's identifier for the result."),
            eslogger("right_name", .string),
        ] + named("rule_class", "The es_authorization_rule_class_t.") + [eslogger("granted", .boolean)])
        let profile = SchemaObject("A configuration profile: es_profile_t.", [
            eslogger("identifier", .string), eslogger("uuid", .string), eslogger("organization", .string),
            eslogger("display_name", .string), eslogger("scope", .string),
        ] + named("install_source", "The es_profile_source_t."))
        return [
            event(ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION,
                  "A process asked for authorization rights: es_event_authorization_petition_t.", [
                eslogger("instigator", .nullable(.ref("process"))),
                eslogger("petitioner", .nullable(.ref("process"))),
                addition("flags_array", .array(.string), "The names of the flags `flags` has."),
                eslogger("flags", .integer),
                eslogger("right_count", .integer),
                eslogger("rights", .array(.string)),
            ] + tokens("instigator", "petitioner")),
            event(ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT,
                  "Authorization rights judged: es_event_authorization_judgement_t.", [
                eslogger("return_code", .integer),
                eslogger("result_count", .integer),
                eslogger("results", .array(.object(result))),
                eslogger("instigator", .nullable(.ref("process"))),
                eslogger("petitioner", .nullable(.ref("process"))),
            ] + tokens("instigator", "petitioner")),
            event(ES_EVENT_TYPE_NOTIFY_PROFILE_ADD, "A configuration profile installed: es_event_profile_add_t.", [
                eslogger("is_update", .boolean),
                eslogger("instigator", .nullable(.ref("process"))),
                eslogger("profile", .object(profile)),
            ] + tokens("instigator")),
            event(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, "A TCC permission changed: es_event_tcc_modify_t.", [
                eslogger("service", .string),
                eslogger("identity", .string),
            ] + named("identity_type", "The es_tcc_identity_type_t.")
              + named("update_type", "The es_tcc_event_type_t.") + [
                eslogger("instigator_token", .ref("audit_token")),
                eslogger("instigator", .nullable(.ref("process"))),
                eslogger("responsible_token", .nullable(.ref("audit_token"))),
                eslogger("responsible", .nullable(.ref("process"))),
            ] + named("right", "The es_tcc_authorization_right_t.")
              + named("reason", "The es_tcc_authorization_reason_t.")),
            gatekeeperOverride,
        ]
    }
    
    /// Audit tokens added in message version 8, which Mac Monitor writes as `null` before it.
    ///
    /// - Parameter processes: The processes whose `<process>_token` keys these are.
    /// - Returns: The keys.
    private static func tokens(_ processes: String...) -> [SchemaKey] {
        processes.map { eslogger("\($0)_token", .nullable(.ref("audit_token")), "null before message version 8.") }
    }
    
    /// A background task event: who added or removed it, the app, and the item.
    ///
    /// - Parameters:
    ///   - type: The event's type.
    ///   - description: What the event is.
    ///   - keys: The event's own keys.
    /// - Returns: The event.
    private static func launchItem(_ type: es_event_type_t, _ description: String, _ keys: [SchemaKey]) -> SchemaEvent {
        event(type, description, [
            eslogger("instigator", .nullable(.ref("process"))),
            eslogger("app", .nullable(.ref("process"))),
            eslogger("item", .ref("launch_item")),
        ] + keys + [
            eslogger("instigator_token", .nullable(.ref("audit_token"))),
            eslogger("app_token", .nullable(.ref("audit_token"))),
        ])
    }
    
    /// A Gatekeeper override: `es_event_gatekeeper_user_override_t`.
    private static var gatekeeperOverride: SchemaEvent {
        event(ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE,
              "A user overrode Gatekeeper: es_event_gatekeeper_user_override_t.",
              named("file_type", "The es_gatekeeper_user_override_file_type_t.") + [
            eslogger("file", .either([.string, .ref("file"), .null]),
                     "The file's path, or the file, as `file_type` says; null when the path is NULL.",
                     absent: Absence("`file_type` names neither")),
            addition("file_path", .string, "The file's path, when `file_type` names a path.",
                     absent: Absence("`file_type` doesn't name a path")),
            eslogger("sha256", .nullable(.pattern(.sha256)),
                     "The file's SHA-256 in uppercase hex, given for a file under 100 MB. Mac Monitor writes NULL when "
                        + "there's none, where eslogger writes null."),
            eslogger("signing_info", .nullable(.ref("signed_file_info"))),
        ])
    }
}
