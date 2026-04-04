import Foundation

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
print(MemoryLayout<EventIndexEntry>.stride)
