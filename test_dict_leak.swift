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

let start = currentPhysicalFootprintBytes() ?? 0
var dict: [String: [Int]] = [:]
let key = "target1"
for i in 0..<150_000 {
    dict[key, default: []].append(i)
}
let end = currentPhysicalFootprintBytes() ?? 0
print("Growth per append: \(Double(end - start) / 150_000.0) bytes")
