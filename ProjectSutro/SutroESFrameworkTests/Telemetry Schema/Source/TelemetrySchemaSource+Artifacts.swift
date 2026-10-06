//
//  TelemetrySchemaSource+Artifacts.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Shared definitions
extension TelemetrySchemaSource {
    /// The objects many events share, by their names in `$defs`.
    static var artifacts: [String: SchemaObject] {
        ["process": process, "file": file, "stat": stat, "audit_token": auditToken, "thread": thread,
         "action": action, "launched_by_parent": launchedByParent, "launch_item": launchItem, "od_member": odMember,
         "thread_state": threadState, "signed_file_info": signedFileInfo]
    }
    
    /// A process: `es_process_t`.
    static var process: SchemaObject {
        SchemaObject("A process: es_process_t, as eslogger writes it, with Mac Monitor's additions.", [
            addition("id", .pattern(.uuid), "Mac Monitor's identifier for the process in this record."),
            eslogger("start_time", .pattern(.timeval)),
            addition("pid", .integer, "The process ID, from `audit_token`."),
            eslogger("ppid", .integer),
            eslogger("original_ppid", .integer),
            eslogger("group_id", .integer),
            eslogger("session_id", .integer),
            eslogger("audit_token", .ref("audit_token")),
            addition("audit_token_string", .string, "`audit_token` as one line of text."),
            eslogger("parent_audit_token", .ref("audit_token")),
            addition("parent_audit_token_string", .string, "`parent_audit_token` as one line of text."),
            eslogger("responsible_audit_token", .ref("audit_token")),
            addition("responsible_audit_token_string", .string, "`responsible_audit_token` as one line of text."),
            eslogger("codesigning_flags", .integer),
            eslogger("signing_id", .nullable(.string),
                     "null when Endpoint Security gives none, or in a record from Mac Monitor before 2.2.0, which left "
                     + "out an empty one."),
            eslogger("team_id", .nullable(.string)),
            eslogger("cdhash", .pattern(.cdhash)),
            addition("is_adhoc_signed", .boolean, "Whether `codesigning_flags` has CS_ADHOC."),
            eslogger("cs_validation_category", .integer,
                     absent: Absence("the message's version is before 10 (macOS 26)")),
            addition("cs_validation_category_string", .string, "The name of `cs_validation_category`.",
                     absent: Absence("`cs_validation_category` is")),
            eslogger("is_es_client", .boolean),
            eslogger("is_platform_binary", .boolean),
            eslogger("executable", .ref("file")),
            addition("file_quarantine_type", .values(FileQuarantineType.allCases.map(\.rawValue)),
                     "Whether File Quarantine applies to the executable: opted in, forced by Apple, or disabled."),
            addition("codesigning_type", .values(CodeSigningType.allCases.map(\.rawValue)),
                     "How the executable is signed: from `codesigning_flags`, or its certificates."),
            eslogger("tty", .nullable(.ref("file"))),
            addition("euid", .integer, "The effective user ID, from `audit_token`."),
            addition("ruid", .integer, "The real user ID, from `audit_token`."),
            addition("euid_human", .string, "The name of the effective user.",
                     absent: Absence("the user has no name on the Mac that wrote the record, or isn't a system "
                                     + "account in a trace opened from another Mac")),
            addition("ruid_human", .string, "The name of the real user.",
                     absent: Absence("the user has no name on the Mac that wrote the record, or isn't a system "
                                     + "account in a trace opened from another Mac")),
        ])
    }
    
    /// A file: `es_file_t`.
    static var file: SchemaObject {
        SchemaObject("A file: es_file_t.", [
            eslogger("path", .string),
            addition("name", .string, "The last component of `path`."),
            eslogger("stat", .ref("stat")),
            eslogger("path_truncated", .boolean),
        ])
    }
    
    /// A file's `stat`.
    static var stat: SchemaObject {
        SchemaObject("A file's struct stat.", [
            eslogger("st_dev", .integer), eslogger("st_blksize", .integer), eslogger("st_blocks", .integer),
            eslogger("st_flags", .integer), eslogger("st_gen", .integer), eslogger("st_gid", .integer),
            eslogger("st_ino", .integer, "Unsigned: 2^63 or more on some network file systems."),
            eslogger("st_mode", .integer), eslogger("st_nlink", .integer), eslogger("st_rdev", .integer),
            eslogger("st_size", .integer), eslogger("st_uid", .integer),
            eslogger("st_atimespec", .pattern(.timespec)), eslogger("st_birthtimespec", .pattern(.timespec)),
            eslogger("st_ctimespec", .pattern(.timespec)), eslogger("st_mtimespec", .pattern(.timespec)),
        ])
    }
    
    /// An audit token: `audit_token_t`, by its fields.
    static var auditToken: SchemaObject {
        SchemaObject("An audit_token_t, by its fields.", ["pid", "euid", "ruid", "rgid", "egid", "asid", "auid",
                                                         "pidversion"].map { eslogger($0, .integer) })
    }
    
    /// The thread that took the action: `es_thread_t`.
    static var thread: SchemaObject {
        SchemaObject("The thread that took the action: es_thread_t.", [eslogger("thread_id", .integer)])
    }
    
    /// The message's action: a notify event's result.
    static var action: SchemaObject {
        let auth = SchemaObject("An ES_RESULT_TYPE_AUTH result.", [
            eslogger("auth", .integer),
            addition("auth_human", .string, "The name of `auth`: ES_AUTH_RESULT_ALLOW or ES_AUTH_RESULT_DENY."),
        ])
        let flags = SchemaObject("An ES_RESULT_TYPE_FLAGS result.", [eslogger("flags", .integer)])
        let result = SchemaObject("A notify event's result.", [
            eslogger("result_type", .integer),
            addition("result_type_human", .string, "The name of `result_type`.",
                     absent: Absence("`result_type` is neither ES_RESULT_TYPE_AUTH nor ES_RESULT_TYPE_FLAGS",
                                     observable: false)),
            eslogger("result", .either([.object(auth), .object(flags)]),
                     absent: Absence("`result_type` is neither ES_RESULT_TYPE_AUTH nor ES_RESULT_TYPE_FLAGS",
                                     observable: false)),
        ])
        return SchemaObject("The message's action.", [eslogger("result", .object(result))])
    }
    
    /// The launched-by parent of the process an exec or fork creates.
    static var launchedByParent: SchemaObject {
        let job = SchemaObject("The launchd job that started the process.", [
            addition("label", .string, "The job's label, from XPC_SERVICE_NAME in its exec environment."),
        ])
        return SchemaObject("The process that really caused another to run, and how Mac Monitor knows.", [
            addition("source", .values(LaunchedByParent.Source.allCases.map(\.rawValue)), "The signal that named it."),
            addition("audit_token", .nullable(.ref("audit_token")),
                     "The launched-by parent's audit token, as eslogger writes one; null when only its pid is known."),
            addition("pid", .nullable(.integer), "The launched-by parent's pid."),
            addition("path", .nullable(.string), "The launched-by parent's executable, when known."),
            addition("launchd_job", .nullable(.object(job)),
                     "The launchd job that started the process, for a direct launchd child with a label."),
            addition("resolved_by", .values(LaunchedByParent.ResolvedBy.allCases.map(\.rawValue)),
                     "Who resolved it: the Security Extension, the app, or the opening of a trace."),
        ])
    }
    
    /// A background task's launch item: `es_btm_launch_item_t`.
    static var launchItem: SchemaObject {
        SchemaObject("A launch item: es_btm_launch_item_t.", named("item_type", "The item's es_btm_item_type_t.") + [
            eslogger("item_url", .string),
            addition("item_path", .string, "`item_url` as a path."),
            eslogger("app_url", .nullable(.string)),
            addition("app_path", .nullable(.string), "`app_url` as a path."),
            eslogger("legacy", .boolean),
            eslogger("managed", .boolean),
            eslogger("uid", .integer),
            addition("uid_human", .nullable(.string), "The name of `uid`, when it's a system account."),
            addition("plist_contents", .string, "The item's property list, read when the event was recorded.",
                     absent: Absence("the property list couldn't be read")),
        ])
    }
    
    /// A group member of an Open Directory event: `es_od_member_id_t`.
    static var odMember: SchemaObject {
        SchemaObject("A group member: es_od_member_id_t.", [
            eslogger("member_type", .integer, "A user's name (0), a user's UUID (1) or a group's UUID (2)."),
            eslogger("member_value", .nullable(.string),
                     "The user's name, or the UUID; null in a record from Mac Monitor before 2.2.0."),
        ])
    }
    
    /// A remote thread's state: `es_thread_state_t`.
    static var threadState: SchemaObject {
        SchemaObject("A thread's state: es_thread_state_t.", [
            eslogger("flavor", .integer),
            eslogger("state", .null, "eslogger writes no bytes."),
            addition("state_base64", .nullable(.string), "The state's bytes in base64: null when they weren't kept."),
        ])
    }
    
    /// A file's code signing: `es_signed_file_info_t`.
    static var signedFileInfo: SchemaObject {
        SchemaObject("A file's code signing: es_signed_file_info_t.", [
            eslogger("cdhash", .pattern(.cdhash)),
            eslogger("signing_id", .nullable(.string), "null when the signing information has none."),
            eslogger("team_id", .nullable(.string),
                     "null when the signing information has none, as for ad hoc signing."),
        ])
    }
}
