import Foundation

// Stubs to match EventStore logic
struct EventIndexEntry {
    let id: UUID
    let mmapOffset: Int
    let machTime: Int64
    let darwinTime: Date
    let eventType: Int
    let esEventType: String
    let hasExec: Bool
    let auditTokenString: String
    let parentAuditTokenString: String
    let groupID: Int32
    let sessionID: Int32
    let executablePathHash: UInt64
    let euidHuman: String?
    let targetPathHash: UInt64?
    let targetAuditTokenString: String?
    let targetGroupID: Int32?
    let targetSessionID: Int32?
}

var index: [EventIndexEntry] = []
var targetAuditTokenIndex: [String: [Int]] = [:]
var eventIDIndex: [UUID: Int] = [:]
var processGroupIndex: [Int32: [Int]] = [:]
var sessionGroupIndex: [Int32: [Int]] = [:]
var correlatedChildren: [Int: [Int]] = [:]

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

// Simulate inserting 100,000 events
for i in 0..<100_000 {
    let id = UUID()
    let entry = EventIndexEntry(
        id: id, mmapOffset: i * 8000, machTime: 0, darwinTime: Date(), eventType: 1, esEventType: "exec", hasExec: true,
        auditTokenString: "audit1", parentAuditTokenString: "parent1", groupID: 1, sessionID: 1,
        executablePathHash: 0, euidHuman: "root", targetPathHash: 0, targetAuditTokenString: "target1",
        targetGroupID: 1, targetSessionID: 1
    )
    index.append(entry)
    
    eventIDIndex[id] = i
    
    if let targetToken = entry.targetAuditTokenString {
        targetAuditTokenIndex[targetToken, default: []].append(i)
        if let gid = entry.targetGroupID { processGroupIndex[gid, default: []].append(i) }
        if let sid = entry.targetSessionID { sessionGroupIndex[sid, default: []].append(i) }
    }
    processGroupIndex[entry.groupID, default: []].append(i)
    sessionGroupIndex[entry.sessionID, default: []].append(i)
    
    // Phase 3
    let parentToken = entry.auditTokenString
    if let parentIndices = targetAuditTokenIndex[parentToken], let parentIndex = parentIndices.last, parentIndex != i {
        correlatedChildren[parentIndex, default: []].append(i)
    }
}

let end = currentPhysicalFootprintBytes() ?? 0
print("Memory growth per event: \(Double(end - start) / 100_000.0) bytes")

