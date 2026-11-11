//
//  PerformanceSample.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Samples
/// One timed run of a benchmark's body: its wall time, the CPU time every thread of the process spent in it, and how
/// much the process's memory footprint grew.
struct PerformanceSample: Codable, Equatable {
    /// Wall time (`CLOCK_UPTIME_RAW`), in nanoseconds.
    let wallNs: UInt64
    /// CPU time of the whole process (`CLOCK_PROCESS_CPUTIME_ID`), in nanoseconds: it counts Core Data's and the
    /// exporter's queues too.
    let cpuNs: UInt64
    /// The change in `phys_footprint` (what Activity Monitor calls Memory), in bytes. Negative when memory was freed.
    let footprintDeltaBytes: Int64

    /// Time a run of `body`.
    ///
    /// - Parameter body: The work to time.
    /// - Returns: The sample.
    /// - Throws: What `body` throws.
    static func taking(_ body: () throws -> Void) rethrows -> PerformanceSample {
        let footprint = MemoryFootprint.current
        let cpu = clock_gettime_nsec_np(CLOCK_PROCESS_CPUTIME_ID)
        let wall = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        try body()
        let wallEnd = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        let cpuEnd = clock_gettime_nsec_np(CLOCK_PROCESS_CPUTIME_ID)
        return PerformanceSample(wallNs: wallEnd - wall, cpuNs: cpuEnd - cpu,
                                 footprintDeltaBytes: MemoryFootprint.current - footprint)
    }
}


// MARK: - Statistics
/// A summary of a benchmark's samples.
struct PerformanceStatistics: Codable, Equatable {
    let min, median, mean, max, stddev: Double

    /// - Parameter values: The values, at least one.
    init(_ values: [Double]) {
        let sorted = values.sorted()
        let count = Double(sorted.count)
        let middle = sorted.count / 2
        min = sorted.first ?? 0
        max = sorted.last ?? 0
        median = sorted.isEmpty ? 0 : sorted.count % 2 == 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
        let mean = sorted.reduce(0, +) / Swift.max(count, 1)
        let squares = sorted.reduce(0) { $0 + ($1 - mean) * ($1 - mean) }
        self.mean = mean
        stddev = count > 1 ? (squares / (count - 1)).squareRoot() : 0
    }
}


// MARK: - Memory footprint
/// The process's memory footprint, as `task_info(TASK_VM_INFO)` reports it.
enum MemoryFootprint {
    /// `phys_footprint` now, in bytes, or 0 if the kernel won't say.
    static var current: Int64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? Int64(info.phys_footprint) : 0
    }
}
