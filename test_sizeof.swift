import Foundation

struct TimeVal: Codable, Hashable {
    var tv_sec: Int64 = 0
    var tv_usec: Int32 = 0
}

struct AuditToken: Codable, Hashable {
    var val: [UInt32] = Array(repeating: 0, count: 8)
}

struct File: Codable, Hashable {
    var path: String = ""
    var path_truncated: Bool = false
    var stat: String = ""
}

enum CodeSigningType: String, Codable, Hashable {
    case platform = "PLATFORM"
    case unknown = "UNKNOWN"
}

enum FileQuarantineType: String, Codable, Hashable {
    case optIn = "OPT_IN"
}

struct Process: Codable, Hashable {
    var id = UUID()
    var start_time: TimeVal = TimeVal()
    var pid: Int32 = 0, ppid: Int32 = 0, original_ppid: Int32 = 0
    var group_id: Int32 = 0, session_id: Int32 = 0
    var codesigning_flags: Int64 = 0
    var cdhash: String? = nil, signing_id: String? = nil, team_id: String? = nil
    var cs_validation_category: Int32? = nil
    var audit_token: AuditToken? = nil, responsible_audit_token: AuditToken? = nil, parent_audit_token: AuditToken? = nil
    var audit_token_string: String = "", responsible_audit_token_string: String = "", parent_audit_token_string: String = ""
    var executable: File? = nil
    var is_platform_binary: Bool = false, is_es_client: Bool = false
    var tty: File? = nil
    var euid: Int? = nil, ruid: Int? = nil
    var euid_human: String? = nil, ruid_human: String? = nil
    var codesigning_type: CodeSigningType = .unknown
    var file_quarantine_type: FileQuarantineType = .optIn
    var is_adhoc_signed: Bool = false, get_task_allow: Bool = false, allow_jit: Bool = false, rootless: Bool = false, skip_lv: Bool = false
    var cs_validation_category_string: String? = nil
}

struct Thread: Codable, Hashable {
    var thread_id: UInt64 = 0
}

struct ActionResultWrapper: Codable, Hashable {
    var result: Int = 0
}

struct Message: Codable, Hashable {
    var id = UUID()
    var version: Int = 0, schema_version: Int = 0
    var seq_num: Int? = nil, global_seq_num: Int? = nil
    var time: String = ""
    var mach_time: Int64 = 0
    var message_darwin_time: Date = Date()
    var macOS: String = ""
    var sensor_id: String = ""
    var process: Process = Process()
    var thread: Thread = Thread()
    // Mock event
    var event_type: Int = 0
    var es_event_type: String = ""
    var action_type: Int = 0
    var action_type_string: String = ""
    var action: ActionResultWrapper = ActionResultWrapper()
    var context: String? = nil
    var target_path: String? = nil
}

print(MemoryLayout<Process>.stride)
print(MemoryLayout<Message>.stride)
