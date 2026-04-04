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
let fd = open("/tmp/test_mmap.bin", O_RDWR | O_CREAT, 0o644)
ftruncate(fd, 100 * 1024 * 1024)
let ptr = mmap(nil, 100 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
memset(ptr, 0x42, 100 * 1024 * 1024)

let end = currentPhysicalFootprintBytes() ?? 0
print("Footprint growth: \(end - start)")
