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
         "thread_state": threadState, "signed_file_info": signedFileInfo, "launch_item_bundle": launchItemBundle,
         "indicator": indicator, "indicator_undetermined": indicatorUndetermined]
    }
    
    /// An indicator a record lists: one of the saved set's predicates the event matched, with its severity and who
    /// matched it.
    static var indicator: SchemaObject {
        SchemaObject("An indicator from this Mac's saved set that the event matched.", [
            enrichment("id", .pattern(.uuid), "The indicator's identity, the same on every Mac for one Mac Monitor "
                        + "ships."),
            enrichment("name", .string, "What Settings > Indicators calls it, such as Background item added."),
            enrichment("tactic", .nullable(.values(Indicator.Tactic.allCases.map(\.name).sorted())),
                       "The MITRE ATT&CK tactic it's for, by name, or null for none."),
            enrichment("tactic_id", .nullable(.values(Indicator.Tactic.allCases.map(\.identifier).sorted())),
                       "The tactic's ATT&CK identity, such as TA0003, or null for none."),
            enrichment("technique", .nullable(.string),
                       "The ATT&CK technique it finds, such as T1543.001, or null for none."),
            enrichment("severity", .values(IndicatorSeverity.allCases.map(\.rawValue).sorted()),
                       "How strong a sign of malicious activity a match is: high for a strong one, medium for "
                        + "suspicious behavior that has benign uses, low for context and noisy signals. It never "
                        + "changes what matches."),
            enrichment("default", .boolean, "Whether it is one of Mac Monitor's default indicators, which Mac "
                        + "Monitor ships. edited says whether this Mac changed it."),
            enrichment("edited", .boolean, "Whether this Mac changed one Mac Monitor ships: its name, description, "
                        + "symbol, color, predicate, tactic, technique or severity. Always false when default is "
                        + "false."),
            enrichment("evaluated_by", .values(IndicatorEvaluator.known.map(\.rawValue).sorted()),
                       "Who matched it: security_extension, the Security Extension as it captured the event, or "
                        + "export, Mac Monitor as it wrote the record of an event the Security Extension did not "
                        + "evaluate."),
        ])
    }
    
    /// An indicator the Security Extension couldn't rule out for the event: an indicator's keys, and why.
    static var indicatorUndetermined: SchemaObject {
        SchemaObject("An indicator from this Mac's saved set that the Security Extension could not rule out for the "
                        + "event: it may or may not match.", indicator.keys + [
            enrichment("reason", .values(UndeterminedReason.known.map(\.rawValue).sorted()),
                       "Why it wasn't decided: scan_budget when evaluating the event's values exceeded the Security "
                        + "Extension's per-event scan budget, or value_limit when a value that isn't ASCII was "
                        + "longer than the 64 KiB the Security Extension compares."),
        ])
    }

    /// A process: `es_process_t`.
    static var process: SchemaObject {
        SchemaObject("A process: es_process_t, as eslogger writes it, with Mac Monitor's enrichments.", [
            enrichment("id", .pattern(.uuid), "Mac Monitor's identifier for the process in this record."),
            eslogger("start_time", .pattern(.timeval)),
            enrichment("pid", .integer, "The process ID, from `audit_token`."),
            eslogger("ppid", .integer),
            eslogger("original_ppid", .integer),
            eslogger("group_id", .integer),
            eslogger("session_id", .integer),
            eslogger("audit_token", .ref("audit_token")),
            enrichment("audit_token_string", .string, "`audit_token` as one line of text."),
            eslogger("parent_audit_token", .ref("audit_token")),
            enrichment("parent_audit_token_string", .string, "`parent_audit_token` as one line of text."),
            eslogger("responsible_audit_token", .ref("audit_token")),
            enrichment("responsible_audit_token_string", .string, "`responsible_audit_token` as one line of text."),
            eslogger("codesigning_flags", .integer),
            eslogger("signing_id", .nullable(.string),
                     "null when Endpoint Security gives none, or in a record from Mac Monitor before 3.0.0, which left "
                     + "out an empty one."),
            eslogger("team_id", .nullable(.string)),
            eslogger("cdhash", .pattern(.cdhash)),
            enrichment("is_adhoc_signed", .boolean, "Whether `codesigning_flags` has CS_ADHOC."),
            enrichment("codesigning_flag_names", .array(.string),
                       "The names of the flags `codesigning_flags` sets, from cs_blobs.h, in bit order: CS_VALID, "
                       + "CS_RUNTIME (the hardened runtime), CS_LINKER_SIGNED."),
            eslogger("cs_validation_category", .integer,
                     absent: Absence("the message's version is before 10 (macOS 26)")),
            enrichment("cs_validation_category_string", .string, "The name of `cs_validation_category`.",
                     absent: Absence("`cs_validation_category` is")),
            eslogger("is_es_client", .boolean),
            eslogger("is_platform_binary", .boolean),
            eslogger("executable", .ref("file")),
            enrichment("file_quarantine_type", .values(FileQuarantineType.allCases.map(\.rawValue)),
                     "Whether File Quarantine applies to the executable: opted in, forced by Apple, or disabled."),
            enrichment("codesigning_type", .values(CodeSigningType.allCases.map(\.rawValue)),
                     "How the executable is signed: from `codesigning_flags`, or its certificates."),
            eslogger("tty", .nullable(.ref("file"))),
            enrichment("euid", .integer, "The effective user ID, from `audit_token`."),
            enrichment("ruid", .integer, "The real user ID, from `audit_token`."),
            enrichment("euid_human", .string, "The name of the effective user.",
                     absent: Absence("the user has no name on the Mac that wrote the record, or isn't a system "
                                     + "account in a trace opened from another Mac")),
            enrichment("ruid_human", .string, "The name of the real user.",
                     absent: Absence("the user has no name on the Mac that wrote the record, or isn't a system "
                                     + "account in a trace opened from another Mac")),
            enrichment("process_age_ms", .nullable(.integer),
                       "How old the process was at the event: milliseconds from `start_time` to the message's time, "
                       + "rounded. Every process in a record has its own. Negative when the clock stepped back between "
                       + "the two. null when `start_time` is unknown (0). Since telemetry 1.1.0."),
        ])
    }

    /// A file: `es_file_t`.
    static var file: SchemaObject {
        SchemaObject("A file: es_file_t.", [
            eslogger("path", .string),
            enrichment("name", .string, "The last component of `path`."),
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
            enrichment("auth_human", .string, "The name of `auth`: ES_AUTH_RESULT_ALLOW or ES_AUTH_RESULT_DENY."),
        ])
        let flags = SchemaObject("An ES_RESULT_TYPE_FLAGS result.", [eslogger("flags", .integer)])
        let result = SchemaObject("A notify event's result.", [
            eslogger("result_type", .integer),
            enrichment("result_type_human", .string, "The name of `result_type`.",
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
            enrichment("label", .string, "The job's label, from XPC_SERVICE_NAME in its exec environment."),
        ])
        return SchemaObject("The process that really caused another to run, and how Mac Monitor knows.", [
            enrichment("source", .values(LaunchedByParent.Source.allCases.map(\.rawValue)),
                       "The signal that named it."),
            enrichment("audit_token", .nullable(.ref("audit_token")),
                     "The launched-by parent's audit token, as eslogger writes one; null when only its pid is known."),
            enrichment("pid", .nullable(.integer), "The launched-by parent's pid."),
            enrichment("path", .nullable(.string), "The launched-by parent's executable, when known."),
            enrichment("launchd_job", .nullable(.object(job)),
                     "The launchd job that started the process, for a direct launchd child with a label."),
            enrichment("resolved_by", .values(LaunchedByParent.ResolvedBy.allCases.map(\.rawValue)),
                     "Who resolved it: the Security Extension, the app, or the opening of a trace."),
        ])
    }
    
    /// A background task's launch item: `es_btm_launch_item_t`.
    static var launchItem: SchemaObject {
        SchemaObject("A launch item: es_btm_launch_item_t.", named("item_type", "The item's es_btm_item_type_t.") + [
            eslogger("item_url", .string),
            enrichment("item_path", .string, "`item_url` as a path."),
            eslogger("app_url", .nullable(.string)),
            enrichment("app_path", .nullable(.string), "`app_url` as a path."),
            eslogger("legacy", .boolean),
            eslogger("managed", .boolean),
            eslogger("uid", .integer),
            enrichment("uid_human", .nullable(.string), "The name of `uid`, when it's a system account."),
            enrichment("plist_contents", .string,
                       "The item's property list as text, read from the Mac that recorded the event, when it recorded "
                       + "it: an agent's or daemon's launchd plist, or the Info.plist of the bundle an app, login item "
                       + "or user item names (`bundle`). A property list stored in binary is converted to XML. Cut at "
                       + "1 MiB. Not read through a symbolic link below the item's folder, app or bundle.",
                       absent: Absence("the item has no property list, or it couldn't be read")),
            enrichment("bundle", .nullable(.ref("launch_item_bundle")),
                       "The bundle the item names, for an ES_BTM_ITEM_TYPE_APP, ES_BTM_ITEM_TYPE_LOGIN_ITEM or "
                       + "ES_BTM_ITEM_TYPE_USER_ITEM item whose path (absolute, or relative to `app_path`) is a bundle "
                       + "directory. null for other items, for a path that isn't a bundle, and on a remove when the "
                       + "bundle is already gone. Also null when the event wasn't recorded by Mac Monitor 3.1.0 or "
                       + "later (an eslogger trace, or one exported before 3.1.0, opened and exported again): bundles "
                       + "are read only at capture, never when a trace is opened. Since telemetry 1.1.0."),
            enrichment("app_bundle", .nullable(.ref("launch_item_bundle")),
                       "The bundle at `app_path`, the app a helper, agent or daemon belongs to, of any item type. "
                       + "null when the item has no app, its app isn't a bundle, or, on a remove, it's already gone. "
                       + "Also null when the event wasn't recorded by Mac Monitor 3.1.0 or later (an eslogger trace, "
                       + "or one exported before 3.1.0, opened and exported again): bundles are read only at capture, "
                       + "never when a trace is opened. Since telemetry 1.1.0."),
        ])
    }
    
    /// A launch item's bundle: what Mac Monitor read of an app or helper bundle.
    static var launchItemBundle: SchemaObject {
        SchemaObject("An app or helper bundle a launch item names, read by the Security Extension from the Mac that "
                     + "recorded the event, when it recorded it: never when a trace is opened. Each value is null "
                     + "when the bundle doesn't have it or it couldn't be read. Since telemetry 1.1.0.", [
            enrichment("path", .string, "The bundle directory read."),
            enrichment("info_plist_path", .nullable(.string),
                       "The bundle's Info.plist: Contents/Info.plist, or Info.plist at the top of a shallow bundle. "
                       + "Named whether or not it could be read (it isn't through a symbolic link below the bundle); "
                       + "null only in a record that doesn't name it."),
            enrichment("identifier", .nullable(.string), "CFBundleIdentifier, from the bundle's Info.plist."),
            enrichment("name", .nullable(.string), "CFBundleDisplayName, else CFBundleName, from the Info.plist."),
            enrichment("version", .nullable(.string), "CFBundleVersion, from the Info.plist."),
            enrichment("short_version", .nullable(.string), "CFBundleShortVersionString, from the Info.plist."),
            enrichment("executable_path", .nullable(.string),
                       "The bundle's executable, as CFBundle finds it: Contents/MacOS/ and CFBundleExecutable, or "
                       + "CFBundleExecutable beside a shallow bundle's Info.plist, named whether or not the file "
                       + "exists. NSExecutable without CFBundleExecutable, and without either, the file named as the "
                       + "bundle without its extension, when there's one."),
            enrichment("is_ui_element", .nullable(.boolean),
                       "LSUIElement, from the Info.plist, as a Boolean (also when it's written as a number or as "
                       + "\"1\", \"YES\" or \"true\"): the app runs as an agent, without a Dock icon or menu bar."),
            enrichment("is_background_only", .nullable(.boolean),
                       "LSBackgroundOnly, from the Info.plist, read as `is_ui_element` is: the app runs with no user "
                       + "interface at all."),
            enrichment("signing_id", .nullable(.string),
                       "The bundle's signing identifier, from a static read of its signature "
                       + "(SecStaticCodeCreateWithPath and SecCodeCopySigningInformation, without validating it). "
                       + "null for an unsigned bundle."),
            enrichment("team_id", .nullable(.string),
                       "The bundle's team identifier, from its signature. null for Apple platform, adhoc and unsigned "
                       + "bundles."),
            enrichment("codesigning_type", .nullable(.values(CodeSigningType.allCases.map(\.rawValue))),
                       "How the bundle as a whole is signed: PLATFORM when its signature has a platform identifier, "
                       + "ADHOC or UNSIGNED, otherwise APP_STORE or DEVELOPER_ID by its certificates (UNKNOWN for "
                       + "others). null when the signature couldn't be read: also when the Info.plist couldn't be, or "
                       + "a FIFO or other special file is where Security would open it."),
            enrichment("is_quarantined", .integer,
                       "1 if the bundle directory has a com.apple.quarantine attribute, 0 if not, and 2 if it "
                       + "couldn't be found."),
            enrichment("where_froms", .nullable(.array(.string)),
                       "Where the bundle was downloaded from: the strings of the binary property list array in the "
                       + "bundle directory's com.apple.metadata:kMDItemWhereFroms attribute, the download URL and then "
                       + "the page it was found on. null without the attribute."),
            enrichment("birth_time", .nullable(.pattern(.timespec)),
                       "When the bundle directory was created: its st_birthtimespec."),
            enrichment("age_ms", .nullable(.integer),
                       "How old the bundle was at the event: milliseconds from `birth_time` to the message's time, "
                       + "rounded. Negative when the clock stepped back between the two. null when `birth_time` is "
                       + "unknown."),
        ])
    }
    
    /// A group member of an Open Directory event: `es_od_member_id_t`.
    static var odMember: SchemaObject {
        SchemaObject("A group member: es_od_member_id_t.", [
            eslogger("member_type", .integer, "A user's name (0), a user's UUID (1) or a group's UUID (2)."),
            eslogger("member_value", .nullable(.string),
                     "The user's name, or the UUID; null in a record from Mac Monitor before 3.0.0."),
        ])
    }
    
    /// A remote thread's state: `es_thread_state_t`.
    static var threadState: SchemaObject {
        SchemaObject("A thread's state: es_thread_state_t.", [
            eslogger("flavor", .integer),
            eslogger("state", .null, "eslogger writes no bytes."),
            enrichment("state_base64", .nullable(.string), "The state's bytes in base64: null when they weren't kept."),
        ])
    }
    
    /// A file's code signing: `es_signed_file_info_t`.
    static var signedFileInfo: SchemaObject {
        SchemaObject("A file's code signing: es_signed_file_info_t.", [
            eslogger("cdhash", .pattern(.cdhash)),
            eslogger("signing_id", .nullable(.string), "null when the signing information has none."),
            eslogger("team_id", .nullable(.string),
                     "null when the signing information has none, as for adhoc signing."),
        ])
    }
}
