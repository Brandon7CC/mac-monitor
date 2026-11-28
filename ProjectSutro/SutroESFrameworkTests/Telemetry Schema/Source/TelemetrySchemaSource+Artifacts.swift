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
         "indicator": indicator, "indicator_undetermined": indicatorUndetermined, "yara_scan": yaraScan,
         TelemetrySchema.snapshotDefinition: processSnapshotRecord, "process_snapshot": processSnapshot]
    }

    /// A process snapshot's line: the one kind of line that isn't an event's record.
    static var processSnapshotRecord: SchemaObject {
        SchemaObject("A process snapshot's line, the one kind of line that is not an event's record. A line with a "
                     + "`process_snapshot` key follows this definition, not the schema's root. Mac Monitor writes "
                     + "one before the first record that is from a process, or names it in `ancestor_keys`, when "
                     + "nothing earlier in the file describes that process.", [
            enrichment("process_snapshot", .ref("process_snapshot"), "The process the line describes."),
            enrichment("boot_session_uuid", .pattern(.uuid), "Which start of that Mac the snapshot is from, as the "
                        + "records beside it carry.",
                       absent: Absence("the records beside it carry none, or the line is from a test fixture")),
            enrichment("sensor_id", .string, "The Sensor ID of the Mac the snapshot is from, as its events carry.",
                       absent: Absence("the line is from a test fixture, which has every Sensor ID removed")),
        ])
    }

    /// A process a trace has no exec of.
    static var processSnapshot: SchemaObject {
        SchemaObject("A process nothing earlier in the file describes: one that was running before the capture "
                     + "started, or whose exec a filter, a selection or a Clear left out. Its fields are named as a "
                     + "process's are.", [
            enrichment("key", .pattern(.processKey), "The process's key, as `ancestor_keys` names it: its pid, a dot, "
                        + "and its pid version."),
            enrichment("ancestor_keys", .array(.pattern(.processKey)),
                       "The keys of the process's own ancestors, nearest first, as an exec's `ancestor_keys` are. "
                        + "Empty for a child of launchd."),
            enrichment("executable", .object(SchemaObject(nil, [
                enrichment("path", .string, "The executable's path."),
            ])), "The process's executable.", absent: Absence("the process was gone before it could be read")),
            enrichment("command_line", .string, "The process's command line, up to "
                        + "\(ProcessProgram.commandLineLimit) characters.",
                       absent: Absence("it could not be read, or the snapshot was made from a fork")),
            enrichment("signing_id", .string, "The process's signing ID.",
                       absent: Absence("the code is unsigned, or its signature was never read")),
            enrichment("team_id", .string, "The process's team ID.",
                       absent: Absence("the code has none, or its signature was never read")),
            enrichment("codesigning_type", .string, "How the process is signed, as a process's `codesigning_type` "
                        + "says it.", absent: Absence("its signature was never read")),
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
    
    /// What scanning a file with Apple's XProtect rules found: a written file, or the script an exec runs.
    static var yaraScan: SchemaObject {
        let statuses = [YaraScan.scanned, YaraScan.tooLarge, YaraScan.overBudget, YaraScan.busy, YaraScan.unreadable,
                        YaraScan.changed, YaraScan.unavailable, YaraScan.timedOut, YaraScan.tooManyMatches]
        return SchemaObject("What scanning a file with Apple's XProtect rules found: a written file, or the script "
                            + "an exec runs. The rules are the ones the recording Mac's XProtect has, run with the "
                            + "YARA that macOS ships, and a match is what XProtect's rules say of the file. "
                            + "XProtect.yara applies to every file scanned, and XPScripts.yr to AppleScript and JXA, "
                            + "as XProtect itself applies them.", [
            enrichment("status", .values(statuses.sorted()),
                       "scanned, or why the file wasn't: too_large (over 32 MB), over_budget (the scanner's share "
                       + "of the CPU was spent), busy (the scan couldn't finish within half a second behind the "
                       + "files before it), unreadable (gone, dataless, or not readable by the process that wrote "
                       + "or runs it), changed (written again before it was read, so the close of that write is "
                       + "scanned), unavailable (Apple's rules couldn't be loaded on that Mac), timed_out or "
                       + "too_many_matches (libyara stopped the scan). The next exec of a script that was "
                       + "over_budget or busy asks again."),
            enrichment("xprotect_version", .nullable(.string),
                       "The XProtect version whose rules scanned it, such as 5377. null when no rules were loaded."),
            enrichment("rules", .array(.string),
                       "Every rule that matched, by its identifier, such as XProtect_MACOS_OSASCRIPT_BOZO. Empty when "
                       + "none did, or the file wasn't scanned."),
            enrichment("names", .array(.string),
                       "XProtect's name for each rule in `rules`, in the same order, from the rule's description, "
                       + "such as MACOS.OSASCRIPT.BOZO. A rule without a description is named by its identifier."),
            enrichment("report_only", .array(.string),
                       "The rules in `rules` that XProtect only reports and never acts on (match_type = 4), such as "
                       + "its hunting rules, by identifier."),
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
