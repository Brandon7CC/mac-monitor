//
//  IndicatorSetPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import CoreData
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Indicator sets
/// Times a set of indicators as a whole: compiling 2,048, adding one to them, the memory they take, eight lanes
/// sharing one set against each having its own, and Mac Monitor's own matcher on the same events, for the speedup.
/// `<shipped>` is how many indicators Mac Monitor ships.
///
/// | Benchmark | Budget |
/// |---|---|
/// | `indicators.compile.2048` | ≤ 250 ms: compiled off the capture lanes, only when the set loads or changes |
/// | `indicators.compile.add` | ≤ 5 ms |
/// | `indicators.footprint.2048` | ≤ 8 MB: the footprint's growth a sample, and the heap a set holds, printed |
/// | `indicators.concurrent.8` against `.8.copies` | ≥ 85% of the copies' throughput |
/// | `indicators.oracle.{<shipped>,500}` against `indicators.evaluate.recording.{<shipped>,500}` | the speedup |
final class IndicatorSetPerformanceTests: PerformanceTestCase {
    /// Events per lane, for the concurrent benchmarks.
    private static let laneEvents = 20_000
    /// Events in the store, for the oracle.
    private static let storedEvents = 2_000

    /// 2,048 distinct rules compiled, as the Security Extension compiles a saved set it loads.
    func testCompile2048() throws {
        let indicators = try distinctRules(2_048)
        try benchmark("indicators.compile.2048", unit: "set", operations: 1) {
            guard CompiledIndicators(indicators).count == indicators.count else {
                throw BenchmarkFailure("Not compiled")
            }
        }
    }

    /// One rule added to 2,047: only it is compiled, the rest reused from the set before.
    func testCompileAdd() throws {
        let indicators = try distinctRules(2_048)
        let before = CompiledIndicators(Array(indicators.dropLast()))
        try benchmark("indicators.compile.add", unit: "set", operations: 1) {
            let after = CompiledIndicators(indicators, reusing: before)
            guard after.compiledCount == 1 else { throw BenchmarkFailure("Compiled \(after.compiledCount)") }
        }
    }

    /// What a set of 2,048 keeps: each sample compiles one and keeps it, so the footprint grows by a set a sample. Its
    /// time is the compile's. Then the heap a set holds, exactly, is printed: what `malloc` has in use with one kept
    /// against without.
    func testFootprint2048() throws {
        let indicators = try distinctRules(2_048)
        var kept: [CompiledIndicators] = []
        try benchmark("indicators.footprint.2048", unit: "set", operations: 1) {
            autoreleasepool { kept.append(CompiledIndicators(indicators)) }
        }
        kept.removeAll()
        let before = Self.heapInUse
        let set = autoreleasepool { CompiledIndicators(indicators) }
        let held = Self.heapInUse - before
        print(String(format: "[performance] indicators.footprint.2048: %.2f MB of heap for %d rules",
                     Double(held) / 1e6, set.count))
    }

    /// Eight lanes evaluating the shipped rules at once, all on one set.
    func testConcurrentShared() throws {
        let shared = CompiledIndicators(Indicator.defaults)
        try benchmarkLanes("indicators.concurrent.8") { _ in shared }
    }

    /// Eight lanes evaluating the shipped rules at once, each on its own copy of the set.
    func testConcurrentCopies() throws {
        let copies = (0..<8).map { _ in CompiledIndicators(Indicator.defaults) }
        try benchmarkLanes("indicators.concurrent.8.copies") { copies[$0] }
    }

    /// Mac Monitor's matcher, `-O`, on a recording's stored events: the shipped rules.
    func testOracleShipped() throws {
        try benchmarkOracle("indicators.oracle.\(Indicator.defaults.count)", Indicator.defaults)
    }

    /// Mac Monitor's matcher on the same events: 500 distinct rules.
    func testOracle500() throws {
        try benchmarkOracle("indicators.oracle.500", try distinctRules(500))
    }

    /// The Security Extension's evaluation of the oracle's events: the shipped rules.
    func testRecordingShipped() throws {
        try benchmarkRecording("indicators.evaluate.recording.\(Indicator.defaults.count)", Indicator.defaults)
    }

    /// The Security Extension's evaluation of the oracle's events: 500 distinct rules.
    func testRecording500() throws {
        try benchmarkRecording("indicators.evaluate.recording.500", try distinctRules(500))
    }
}


// MARK: - Measuring
extension IndicatorSetPerformanceTests {
    /// Time eight lanes at once, each evaluating a recording's execs and closes on its set, per event.
    ///
    /// Each lane cycles through a few events of its own, as each Endpoint Security client evaluates the one event it
    /// just built, still in its core's cache. Lanes sharing events would time their reference counts instead, and
    /// lanes reading through thousands of events each would time the memory bus.
    ///
    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - set: Each lane's set, by its number.
    /// - Throws: The error making the events or writing the results.
    func benchmarkLanes(_ name: String, set: (Int) -> CompiledIndicators) throws {
        let lanes = try (0..<8).map { _ in
            try indicatorEvents(ES_EVENT_TYPE_NOTIFY_EXEC, count: 8)
                + indicatorEvents(ES_EVENT_TYPE_NOTIFY_CLOSE, count: 8)
        }
        try benchmark(name, operations: 8 * Self.laneEvents) {
            DispatchQueue.concurrentPerform(iterations: 8) { lane in
                let compiled = set(lane), events = lanes[lane]
                var values = MessageValueCache()
                for index in 0..<Self.laneEvents {
                    _ = compiled.hits(for: events[index % events.count], values: &values)
                }
            }
        }
    }

    /// What `malloc` has in use, in every zone, in bytes.
    static var heapInUse: Int {
        var statistics = malloc_statistics_t()
        malloc_zone_statistics(nil, &statistics)
        return Int(statistics.size_in_use)
    }

    /// Time Mac Monitor's matcher on a recording's stored events, per event.
    ///
    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - indicators: The rules.
    /// - Throws: The error storing or fetching the events, or writing the results.
    func benchmarkOracle(_ name: String, _ indicators: [Indicator]) throws {
        let store = try makeExportStore(try recordingEvents(Self.storedEvents))
        let context = store.newBackgroundContext()
        let messages = try context.performAndWait { try context.fetch(ESMessage.request(where: nil, loaded: true)) }
        guard messages.count == Self.storedEvents else { throw BenchmarkFailure("Fetched \(messages.count)") }
        try benchmark(name, operations: messages.count, setUp: { IndicatorMatcher(indicators) }) { matcher in
            context.performAndWait {
                for message in messages { _ = matcher.matches(message) }
            }
        }
    }

    /// Time the Security Extension's evaluation of the oracle's events, as a lane builds them, per event.
    ///
    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - indicators: The rules.
    /// - Throws: The error making the events or writing the results.
    func benchmarkRecording(_ name: String, _ indicators: [Indicator]) throws {
        let messages = try recordingEvents(Self.storedEvents).map(nativeCopy)
        let compiled = CompiledIndicators(indicators)
        var values = MessageValueCache()
        try benchmark(name, operations: messages.count) {
            for message in messages { _ = compiled.hits(for: message, values: &values) }
        }
    }
}
