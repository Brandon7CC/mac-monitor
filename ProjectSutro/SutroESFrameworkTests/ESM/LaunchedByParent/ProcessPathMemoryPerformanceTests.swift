//
//  ProcessPathMemoryPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Naming launched-by parents
/// Times how a capture lane names an exec's or fork's launched-by parent (``ProcessPathMemory``): a parent the lane's
/// events named before, and one it hasn't, whose path `proc_pidpath` reads (``ProcessPath/live``).
final class ProcessPathMemoryPerformanceTests: PerformanceTestCase {
    /// The audit tokens of distinct process images.
    ///
    /// - Parameter count: How many.
    /// - Returns: The tokens.
    private func tokens(_ count: Int) -> [AuditToken] {
        (0..<count).map { AuditToken.fixture(pid: Int32($0 % 30_000 + 100), pidversion: UInt32($0 + 1)) }
    }

    /// Parents the lane remembers, a full generation of them in turn.
    func testRememberedParent() throws {
        let tokens = tokens(ProcessPathMemory.laneCapacity)
        let memory = ProcessPathMemory(capacity: ProcessPathMemory.laneCapacity)
        tokens.forEach { memory.remember($0, path: "/bin/zsh") }
        let rounds = 25
        try benchmark("enrich.process_paths.remembered", unit: "lookup", operations: rounds * tokens.count) {
            for _ in 0..<rounds {
                for token in tokens where memory.path(of: token) == nil {
                    throw BenchmarkFailure("Forgot \(token.pid)")
                }
            }
        }
    }

    /// Parents the lane hasn't seen: this process's path is read live for each, then remembered.
    func testParentReadLive() throws {
        let lookups = 5_000
        let pid = getpid()
        try benchmark("enrich.process_paths.live", unit: "lookup", operations: lookups, setUp: {
            (ProcessPathMemory(capacity: ProcessPathMemory.laneCapacity), tokens(lookups))
        }) { memory, tokens in
            for token in tokens where memory.path(of: pid, token, reading: ProcessPath.live) == nil {
                throw BenchmarkFailure("No path for \(pid)")
            }
        }
    }
}
