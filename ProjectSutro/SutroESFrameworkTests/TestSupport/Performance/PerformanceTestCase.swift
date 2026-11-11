//
//  PerformanceTestCase.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest


// MARK: - Performance tests
/// A test case of benchmarks, which run only when ``PerformanceRun/isEnabled``: the suite's usual run skips them.
///
/// Each test runs one ``benchmark(_:unit:operations:setUp:_:)``, as XCTest allows one `measure` per test. Xcode's
/// report shows XCTest's clock, CPU and memory metrics for it, and ``PerformanceReport/shared`` keeps its samples, by
/// name, in the run's results file.
class PerformanceTestCase: XCTestCase {
    /// The metrics Xcode's report shows: wall time, CPU time and memory, for the whole process.
    private static var metrics: [XCTMetric] { [XCTClockMetric(), XCTCPUMetric(), XCTMemoryMetric()] }

    override func setUpWithError() throws {
        try super.setUpWithError()
        try XCTSkipUnless(PerformanceRun.isEnabled, PerformanceRun.skipReason)
    }

    /// Measure a body that does `operations` operations, with no setup of its own.
    ///
    /// - Parameters:
    ///   - name: The benchmark's stable name, such as `capture.serialize.open`.
    ///   - unit: What one operation is.
    ///   - operations: The operations each run of `body` does.
    ///   - body: The work.
    /// - Throws: What `body` throws, or the error writing the results file.
    func benchmark(_ name: String, unit: String = "event", operations: Int, _ body: () throws -> Void) throws {
        try benchmark(name, unit: unit, operations: operations, setUp: {}, { _ in try body() })
    }

    /// Measure a body that does `operations` operations, each sample on state made for it outside the timing.
    ///
    /// The body runs once to warm up (lazy statics, caches, page faults), then once per sample
    /// (``PerformanceRun/sampleCount``).
    ///
    /// - Parameters:
    ///   - name: The benchmark's stable name. Results files are compared by it, so keep it when the test changes.
    ///   - unit: What one operation is.
    ///   - operations: The operations each run of `body` does.
    ///   - setUp: Makes a sample's state, untimed: a fresh store to insert into, a file to read.
    ///   - body: The work, on that state.
    /// - Throws: What `setUp` or `body` throws, or the error writing the results file.
    func benchmark<State>(_ name: String, unit: String = "event", operations: Int, setUp: () throws -> State,
                          _ body: (State) throws -> Void) throws {
        try body(try setUp())
        let options = XCTMeasureOptions()
        options.iterationCount = PerformanceRun.sampleCount
        options.invocationOptions = [.manuallyStart, .manuallyStop]
        var samples: [PerformanceSample] = []
        var failure: Error?
        measure(metrics: Self.metrics, options: options) {
            var started = false
            do {
                let state = try setUp()
                startMeasuring()
                started = true
                samples.append(try PerformanceSample.taking { try body(state) })
            } catch {
                failure = failure ?? error
            }
            if started { stopMeasuring() }
        }
        if let failure { throw failure }
        let result = PerformanceResult(name: name, test: self.name, unit: unit, operations: operations,
                                       samples: Array(samples.suffix(options.iterationCount)))
        try PerformanceReport.shared.add(result)
        print("[performance] \(result.summary)")
    }
}


// MARK: - Failures
/// Why a benchmark's body couldn't do its work: the benchmark fails rather than time the wrong thing.
struct BenchmarkFailure: Error, CustomStringConvertible {
    let description: String
    
    /// - Parameter description: What went wrong.
    init(_ description: String) {
        self.description = description
    }
}
