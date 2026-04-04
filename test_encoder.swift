import Foundation
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

struct Message: Codable {
    var name: String = "Test"
    var id: UUID = UUID()
}

let start = currentPhysicalFootprintBytes() ?? 0
for _ in 0..<100 {
    autoreleasepool {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let messages = (0..<1000).map { _ in Message() }
        let _ = try! messages.map { msg in (try encoder.encode(msg), msg) }
    }
}
let end = currentPhysicalFootprintBytes() ?? 0
print("Growth with autorelease: \(end - start)")

let start2 = currentPhysicalFootprintBytes() ?? 0
for _ in 0..<100 {
    let encoder = PropertyListEncoder()
    encoder.outputFormat = .binary
    let messages = (0..<1000).map { _ in Message() }
    let _ = try! messages.map { msg in (try encoder.encode(msg), msg) }
}
let end2 = currentPhysicalFootprintBytes() ?? 0
print("Growth without autorelease: \(end2 - start2)")
