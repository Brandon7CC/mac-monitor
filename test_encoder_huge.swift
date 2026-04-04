import Foundation

struct Message: Codable {
    var text = String(repeating: "A", count: 8000)
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

let messages = (0..<10_000).map { _ in Message() }
let start = currentPhysicalFootprintBytes() ?? 0
for _ in 0..<10 {
    autoreleasepool {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let _ = try! messages[0..<1000].map { try encoder.encode($0) }
    }
}
let end = currentPhysicalFootprintBytes() ?? 0
print("Growth with autorelease: \(Double(end - start) / 10_000.0) bytes/event")
