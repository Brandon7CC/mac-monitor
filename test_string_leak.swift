import Foundation

struct Message: Codable {
    var shortString: String
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

let encoder = PropertyListEncoder()
encoder.outputFormat = .binary
let dummyData = String(repeating: "A", count: 8000)
var binaryPayloads: [Data] = []
for _ in 0..<1000 {
    let dict: [String: String] = ["shortString": "B", "largePayload": dummyData]
    let data = try! encoder.encode(dict)
    binaryPayloads.append(data)
}

let decoder = PropertyListDecoder()
var extractedStrings: [String] = []

let start = currentPhysicalFootprintBytes() ?? 0
for payload in binaryPayloads {
    let msg = try! decoder.decode(Message.self, from: payload)
    extractedStrings.append(msg.shortString)
}
let end = currentPhysicalFootprintBytes() ?? 0

print("Growth: \(Double(end - start) / 1000.0) bytes/string")

var extractedStringsCopied: [String] = []
let start2 = currentPhysicalFootprintBytes() ?? 0
for payload in binaryPayloads {
    let msg = try! decoder.decode(Message.self, from: payload)
    extractedStringsCopied.append(String(msg.shortString))
}
let end2 = currentPhysicalFootprintBytes() ?? 0
print("Growth copied: \(Double(end2 - start2) / 1000.0) bytes/string")
