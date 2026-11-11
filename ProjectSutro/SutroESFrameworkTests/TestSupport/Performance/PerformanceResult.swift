//
//  PerformanceResult.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Results
/// What one benchmark measured: per operation for time, per sample for memory.
struct PerformanceResult: Codable, Equatable {
    /// The benchmark's stable name, which results files are compared by: `capture.serialize.open`.
    let name: String
    /// The test that ran it: `-[MessageSerializerPerformanceTests testOpen]`.
    let test: String
    /// What one operation is: `event`, `lookup`, `file`.
    let unit: String
    /// Operations per sample.
    let operations: Int
    /// Wall and CPU time per operation, in nanoseconds.
    let wallNs: PerformanceStatistics
    let cpuNs: PerformanceStatistics
    /// The footprint's growth per sample, in bytes.
    let footprintDeltaBytes: PerformanceStatistics
    /// Each sample, as timed.
    let samples: [PerformanceSample]

    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - test: The test that ran it.
    ///   - unit: What one operation is.
    ///   - operations: Operations per sample.
    ///   - samples: The samples, at least one.
    init(name: String, test: String, unit: String, operations: Int, samples: [PerformanceSample]) {
        self.name = name
        self.test = test
        self.unit = unit
        self.operations = operations
        self.samples = samples
        let perOperation = Double(Swift.max(operations, 1))
        wallNs = PerformanceStatistics(samples.map { Double($0.wallNs) / perOperation })
        cpuNs = PerformanceStatistics(samples.map { Double($0.cpuNs) / perOperation })
        footprintDeltaBytes = PerformanceStatistics(samples.map { Double($0.footprintDeltaBytes) })
    }

    /// The median wall and CPU time per operation, as a log line: `capture.serialize.open: 10.12 µs/event (CPU
    /// 10.08 µs), 10 × 2000`.
    var summary: String {
        let microseconds = { (nanoseconds: Double) in String(format: "%.3f µs", nanoseconds / 1_000) }
        return "\(name): \(microseconds(wallNs.median))/\(unit) (CPU \(microseconds(cpuNs.median))), "
            + "\(samples.count) × \(operations)"
    }
}
