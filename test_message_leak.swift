import Foundation

struct TimeVal: Codable { var tv_sec: Int64 = 0; var tv_usec: Int32 = 0 }
struct AuditToken: Codable { var val: [UInt32] = Array(repeating: 0, count: 8) }
struct File: Codable { var path: String = "/usr/bin/some_path_that_is_realistic"; var path_truncated: Bool = false; var stat: String = "stat_string" }
enum CodeSigningType: String, Codable { case unknown = "UNKNOWN" }
enum FileQuarantineType: String, Codable { case optIn = "OPT_IN" }
struct Process: Codable {
    var id = UUID()
    var start_time = TimeVal()
    var pid: Int32 = 1234, ppid: Int32 = 123, original_ppid: Int32 = 12
    var group_id: Int32 = 1234, session_id: Int32 = 1234
    var codesigning_flags: Int64 = 0x1234
    var cdhash: String? = "1234567890abcdef", signing_id: String? = "com.apple.test", team_id: String? = "team"
    var cs_validation_category: Int32? = 1
    var audit_token: AuditToken? = AuditToken(), responsible_audit_token: AuditToken? = AuditToken(), parent_audit_token: AuditToken? = AuditToken()
    var audit_token_string: String = "audit_string_1234567890", responsible_audit_token_string: String = "audit_string_1234567890", parent_audit_token_string: String = "audit_string_1234567890"
    var executable: File? = File()
    var is_platform_binary: Bool = true, is_es_client: Bool = false
    var tty: File? = File()
    var euid: Int? = 0, ruid: Int? = 0
    var euid_human: String? = "root", ruid_human: String? = "root"
    var codesigning_type: CodeSigningType = .unknown
    var file_quarantine_type: FileQuarantineType = .optIn
    var is_adhoc_signed: Bool = false, get_task_allow: Bool = false, allow_jit: Bool = false, rootless: Bool = false, skip_lv: Bool = false
    var cs_validation_category_string: String? = "category"
}
struct Thread: Codable { var thread_id: UInt64 = 12345 }
struct ActionResultWrapper: Codable { var result: Int = 0 }
enum EventType: Codable {
    case notifyExec(ExecEvent)
    struct ExecEvent: Codable { var target: Process }
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self { case .notifyExec(let evt): try container.encode(evt) }
    }
}
struct Message: Codable {
    var id = UUID()
    var version: Int = 1, schema_version: Int = 1
    var seq_num: Int? = 1, global_seq_num: Int? = 1
    var time: String = "2023-10-10T10:10:10.000Z"
    var mach_time: Int64 = 1234567890
    var message_darwin_time: Date = Date()
    var macOS: String = "13.0"
    var sensor_id: String = "SENSOR-1"
    var process: Process = Process()
    var thread: Thread = Thread()
    var event: EventType = .notifyExec(EventType.ExecEvent(target: Process()))
    var event_type: Int = 1
    var es_event_type: String = "notify_exec"
    var action_type: Int = 1
    var action_type_string: String = "ES_ACTION_TYPE_NOTIFY"
    var action: ActionResultWrapper = ActionResultWrapper()
    var context: String? = "context"
    var target_path: String? = "/usr/bin/target"
}

func currentPhysicalFootprintBytes() -> UInt64? {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.stride / MemoryLayout<natural_t>.stride)
    let kerr = withUnsafeMutablePointer(to: &info) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), intPtr, &count)
        }
    }
    return kerr == KERN_SUCCESS ? info.phys_footprint : nil
}

let start = currentPhysicalFootprintBytes() ?? 0
let messages = (0..<150_000).map { _ in Message() }
for _ in 0..<100 {
    autoreleasepool {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let _ = try! messages[0..<1500].map { try encoder.encode($0) }
    }
}
let end = currentPhysicalFootprintBytes() ?? 0
print("Growth with autorelease: \(Double(end - start) / 150_000.0) bytes/event")
