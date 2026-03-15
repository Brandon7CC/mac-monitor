//
//  StressTestUITests.swift
//  ProjectSutroUITests
//
//  XCUITest that launches the app with --stress-test arguments,
//  waits for the stress test to complete, reads the JSON results file,
//  and asserts on performance thresholds.
//
//  This enables AI agents to make code changes, run `xcodebuild test`,
//  and measure the impact on UI responsiveness automatically.
//
//  SETUP REQUIRED:
//  The user must create a UI Testing Bundle target in Xcode:
//    File -> New -> Target -> UI Testing Bundle
//  Name it "ProjectSutroUITests" and set ProjectSutro as the target application.
//

import XCTest

// MARK: - Result types (duplicated here because XCUITest runs in a separate process)

/// Mirrors MainThreadMetrics from the app.
struct TestMainThreadMetrics: Codable {
    let sampleCount: Int
    let avgLatencyMs: Double
    let p50LatencyMs: Double
    let p95LatencyMs: Double
    let p99LatencyMs: Double
    let maxStallMs: Double
    let droppedFrames60fps: Int
    let droppedFrames30fps: Int
    let droppedFrames100ms: Int
}

/// Mirrors StressTestResults from the app.
struct TestStressResults: Codable {
    let config: ConfigOutput
    let mainThread: TestMainThreadMetrics
    let pipeline: PipelineOutput
    let memory: MemoryOutput

    struct ConfigOutput: Codable {
        let eventsPerSecond: Int
        let durationSeconds: Int
        let fixtureEventCount: Int
    }

    struct PipelineOutput: Codable {
        let totalEventsInserted: Int
        let actualDurationSec: Double
        let effectiveEventsPerSec: Double
    }

    struct MemoryOutput: Codable {
        let startPhysicalFootprintBytes: UInt64
        let peakPhysicalFootprintBytes: UInt64
        let endPhysicalFootprintBytes: UInt64
        let totalGrowthBytes: UInt64
        let totalBytesPerInsertedEvent: Double
        let startMappedAllocatedBytes: UInt64
        let endMappedAllocatedBytes: UInt64
        let mappedAllocatedGrowthBytes: UInt64
        let mappedAllocatedBytesPerInsertedEvent: Double
        let startMappedUsedBytes: UInt64
        let endMappedUsedBytes: UInt64
        let mappedUsedGrowthBytes: UInt64
        let mappedUsedBytesPerInsertedEvent: Double
        let residentGrowthBytes: UInt64
        let residentBytesPerInsertedEvent: Double
    }
}

/// Error result when the stress test fails to run.
struct TestStressError: Codable {
    let error: String
}

// MARK: - Performance Thresholds

/// Configurable thresholds for pass/fail assertions.
///
/// These can be tightened as the pipeline is optimized.
enum PerformanceThresholds {
    struct ThresholdSet {
        let p95LatencyMs: Double
        let p99LatencyMs: Double
        let maxStallMs: Double
        let maxDroppedFrames30fpsPercent: Double
        let minEffectiveRatePercent: Double
        let maxResidentBytesPerInsertedEvent: Double
    }

    /// Guardrails are CI-enforced and represent "not catastrophically broken" behavior.
    /// Targets remain strict and are reported for optimization tracking.
    static let guardrail = ThresholdSet(
        p95LatencyMs: 2500.0,
        p99LatencyMs: 3200.0,
        maxStallMs: 4000.0,
        maxDroppedFrames30fpsPercent: 85.0,
        minEffectiveRatePercent: 90.0,
        maxResidentBytesPerInsertedEvent: 6_000.0
    )

    /// Optimization targets (reported in output; non-fatal for now).
    static let target = ThresholdSet(
        p95LatencyMs: 50.0,
        p99LatencyMs: 100.0,
        maxStallMs: 500.0,
        maxDroppedFrames30fpsPercent: 10.0,
        minEffectiveRatePercent: 98.0,
        maxResidentBytesPerInsertedEvent: 1_500.0
    )
}

// MARK: - Test Cases

final class StressTestUITests: XCTestCase {

    /// Maximum time to wait for the stress test to complete (test duration + overhead).
    private let maxWaitSeconds: TimeInterval = 120

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    // MARK: - Baseline Stress Test (5,000 events/sec, 30s)

    /// Runs a baseline stress test at 5,000 events/sec for 30 seconds.
    ///
    /// This exercises the full pipeline: XPC batch -> EventStore -> index -> MMAP ->
    /// schedulePublish -> eventCount -> onChange -> scheduleFilterUpdate ->
    /// executeFilterUpdate -> @State assignment -> SwiftUI Table diff -> render.
    ///
    /// Requires a fixture file. Set the `STRESS_FIXTURE_PATH` environment variable
    /// or place a fixture at `ProjectSutro/TestFixtures/stress-fixture.plist`.
    func testBaselineStress5000() throws {
        let fixturePath = resolveFixturePath()
        let results = try runStressTest(
            rate: 5000,
            duration: 30,
            fixturePath: fixturePath
        )

        assertGuardrailThresholds(results)
        reportTargetThresholds(results)
    }

    /// Fast smoke scenario for rapid iteration in local development and by AI agents.
    func testSmokeStress1000() throws {
        let fixturePath = resolveFixturePath()
        let results = try runStressTest(
            rate: 1000,
            duration: 5,
            fixturePath: fixturePath
        )

        assertGuardrailThresholds(results)
        reportTargetThresholds(results)
    }

    /// Runs a high-volume stress test at 10,000 events/sec for 15 seconds.
    func testHighVolume10000() throws {
        try requireFullStressSuite()

        let fixturePath = resolveFixturePath()
        let results = try runStressTest(
            rate: 10000,
            duration: 15,
            fixturePath: fixturePath
        )

        assertGuardrailThresholds(results)
        reportTargetThresholds(results)
    }

    /// Runs a sustained stress test at 2,000 events/sec for 60 seconds.
    func testSustainedLoad2000() throws {
        try requireFullStressSuite()

        let fixturePath = resolveFixturePath()
        let results = try runStressTest(
            rate: 2000,
            duration: 60,
            fixturePath: fixturePath
        )

        assertGuardrailThresholds(results)
        reportTargetThresholds(results)
    }

    /// Dedicated memory-growth scenario approximating 90K events.
    ///
    /// This test is opt-in because it is longer-running and intentionally strict.
    /// It targets the failure mode where RSS/footprint grows linearly with event count.
    func testMemoryGrowth90000Events() throws {
        try requireMemorySuite()

        let fixturePath = resolveFixturePath()
        let results = try runStressTest(
            rate: 3000,
            duration: 30,
            fixturePath: fixturePath
        )

        // Keep responsiveness guardrails in place for this run.
        assertGuardrailThresholds(results)
        reportTargetThresholds(results)
    }

    // MARK: - Core Test Runner

    /// Launches the app with stress test arguments, waits for results, and parses them.
    private func runStressTest(
        rate: Int,
        duration: Int,
        fixturePath: String?
    ) throws -> TestStressResults {
        let app = XCUIApplication()
        let resultsPath = makeResultsPath(rate: rate, duration: duration)

        // Ensure this run starts clean and cannot read stale output.
        try? FileManager.default.removeItem(atPath: resultsPath)

        // Configure launch arguments
        var args = [
            "--stress-test",
            "--stress-rate", "\(rate)",
            "--stress-duration", "\(duration)",
            "--stress-results", resultsPath
        ]

        if let fixture = fixturePath {
            args.append(contentsOf: ["--stress-fixture", fixture])
        }

        app.launchArguments = args
        app.launch()

        // Wait for results file to appear
        // Total wait = test duration + 2s UI settle + 1.5s post-test flush + buffer
        let totalWait = Double(duration) + 15.0
        let deadline = Date().addingTimeInterval(min(totalWait, maxWaitSeconds))

        var resultsData: Data?
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: resultsPath) {
                // Brief delay to ensure file is fully written (atomic write should handle this,
                // but belt-and-suspenders)
                Thread.sleep(forTimeInterval: 0.5)
                resultsData = FileManager.default.contents(atPath: resultsPath)
                if resultsData != nil { break }
            }
            Thread.sleep(forTimeInterval: 1.0)
        }

        // Terminate the app
        app.terminate()

        guard let data = resultsData else {
            XCTFail("Stress test results file not found at \(resultsPath) after \(totalWait)s")
            throw StressTestError.noResults
        }

        // Check for error result
        if let errorResult = try? JSONDecoder().decode(TestStressError.self, from: data) {
            XCTFail("Stress test failed: \(errorResult.error)")
            throw StressTestError.testFailed(errorResult.error)
        }

        let results = try JSONDecoder().decode(TestStressResults.self, from: data)

        XCTAssertEqual(
            results.config.eventsPerSecond,
            rate,
            "Stress results rate mismatch; expected \(rate), got \(results.config.eventsPerSecond)."
        )

        XCTAssertEqual(
            results.config.durationSeconds,
            duration,
            "Stress results duration mismatch; expected \(duration), got \(results.config.durationSeconds)."
        )

        // Print results between markers for easy agent extraction
        printResults(results)

        return results
    }

    // MARK: - Assertions

    private func assertGuardrailThresholds(_ results: TestStressResults) {
        let mt = results.mainThread
        let pl = results.pipeline
        let cfg = results.config
        let mem = results.memory
        let thresholds = PerformanceThresholds.guardrail

        XCTAssertGreaterThan(
            mt.sampleCount,
            200,
            "Insufficient main thread samples (\(mt.sampleCount)); stress run may not have executed correctly"
        )

        let effectiveRatePercent = cfg.eventsPerSecond > 0
            ? (pl.effectiveEventsPerSec / Double(cfg.eventsPerSecond)) * 100.0
            : 0.0

        XCTAssertGreaterThanOrEqual(
            effectiveRatePercent,
            thresholds.minEffectiveRatePercent,
            "Effective ingestion rate (\(String(format: "%.1f", effectiveRatePercent))%) below guardrail (\(thresholds.minEffectiveRatePercent)%)"
        )

        XCTAssertLessThan(
            mem.residentBytesPerInsertedEvent,
            thresholds.maxResidentBytesPerInsertedEvent,
            "Resident memory growth per inserted event (\(String(format: "%.1f", mem.residentBytesPerInsertedEvent)) B/event) exceeds guardrail (\(String(format: "%.1f", thresholds.maxResidentBytesPerInsertedEvent)) B/event); resident_growth=\(formatBytes(mem.residentGrowthBytes)) total_growth=\(formatBytes(mem.totalGrowthBytes)) mapped_used_growth=\(formatBytes(mem.mappedUsedGrowthBytes))"
        )

        XCTAssertLessThan(
            mt.p95LatencyMs,
            thresholds.p95LatencyMs,
            "P95 main thread latency (\(String(format: "%.2f", mt.p95LatencyMs))ms) exceeds guardrail (\(thresholds.p95LatencyMs)ms)"
        )

        XCTAssertLessThan(
            mt.p99LatencyMs,
            thresholds.p99LatencyMs,
            "P99 main thread latency (\(String(format: "%.2f", mt.p99LatencyMs))ms) exceeds guardrail (\(thresholds.p99LatencyMs)ms)"
        )

        XCTAssertLessThan(
            mt.maxStallMs,
            thresholds.maxStallMs,
            "Max stall (\(String(format: "%.2f", mt.maxStallMs))ms) exceeds guardrail (\(thresholds.maxStallMs)ms)"
        )

        // Check percentage of 30fps drops
        if mt.sampleCount > 0 {
            let dropPercent = Double(mt.droppedFrames30fps) / Double(mt.sampleCount) * 100.0
            XCTAssertLessThan(
                dropPercent,
                thresholds.maxDroppedFrames30fpsPercent,
                "Dropped frames at 30fps (\(String(format: "%.1f", dropPercent))%) exceeds guardrail (\(thresholds.maxDroppedFrames30fpsPercent)%)"
            )
        }
    }

    private func reportTargetThresholds(_ results: TestStressResults) {
        let mt = results.mainThread
        let pl = results.pipeline
        let cfg = results.config
        let mem = results.memory
        let target = PerformanceThresholds.target

        let dropPercent = mt.sampleCount > 0
            ? Double(mt.droppedFrames30fps) / Double(mt.sampleCount) * 100.0
            : 0.0
        let effectiveRatePercent = cfg.eventsPerSecond > 0
            ? (pl.effectiveEventsPerSec / Double(cfg.eventsPerSecond)) * 100.0
            : 0.0

        let targetSummary = [
            "p95<\(target.p95LatencyMs)ms=\(mt.p95LatencyMs < target.p95LatencyMs ? "PASS" : "FAIL")",
            "p99<\(target.p99LatencyMs)ms=\(mt.p99LatencyMs < target.p99LatencyMs ? "PASS" : "FAIL")",
            "max_stall<\(target.maxStallMs)ms=\(mt.maxStallMs < target.maxStallMs ? "PASS" : "FAIL")",
            "30fps_drops<\(target.maxDroppedFrames30fpsPercent)%=\(dropPercent < target.maxDroppedFrames30fpsPercent ? "PASS" : "FAIL")",
            "eff_rate>=\(target.minEffectiveRatePercent)%=\(effectiveRatePercent >= target.minEffectiveRatePercent ? "PASS" : "FAIL")",
            "resident_bytes_per_event<\(String(format: "%.0f", target.maxResidentBytesPerInsertedEvent))=\(mem.residentBytesPerInsertedEvent < target.maxResidentBytesPerInsertedEvent ? "PASS" : "FAIL")"
        ].joined(separator: " ")

        print("TARGETS: \(targetSummary)")
    }

    // MARK: - Output

    private func printResults(_ results: TestStressResults) {
        let mt = results.mainThread
        let pl = results.pipeline
        let cfg = results.config
        let mem = results.memory

        // Delimited output for easy parsing by AI agents
        print("=== STRESS TEST RESULTS ===")
        print("CONFIG: rate=\(cfg.eventsPerSecond)/s duration=\(cfg.durationSeconds)s fixtures=\(cfg.fixtureEventCount)")
        print("PIPELINE: inserted=\(pl.totalEventsInserted) actual_duration=\(String(format: "%.1f", pl.actualDurationSec))s effective_rate=\(String(format: "%.1f", pl.effectiveEventsPerSec))/s")
        print("MEMORY_TOTAL: start=\(formatBytes(mem.startPhysicalFootprintBytes)) peak=\(formatBytes(mem.peakPhysicalFootprintBytes)) end=\(formatBytes(mem.endPhysicalFootprintBytes)) growth=\(formatBytes(mem.totalGrowthBytes)) bytes_per_event=\(String(format: "%.1f", mem.totalBytesPerInsertedEvent))")
        print("MEMORY_MAPPED_ALLOC: start=\(formatBytes(mem.startMappedAllocatedBytes)) end=\(formatBytes(mem.endMappedAllocatedBytes)) growth=\(formatBytes(mem.mappedAllocatedGrowthBytes)) bytes_per_event=\(String(format: "%.1f", mem.mappedAllocatedBytesPerInsertedEvent))")
        print("MEMORY_MAPPED_USED: start=\(formatBytes(mem.startMappedUsedBytes)) end=\(formatBytes(mem.endMappedUsedBytes)) growth=\(formatBytes(mem.mappedUsedGrowthBytes)) bytes_per_event=\(String(format: "%.1f", mem.mappedUsedBytesPerInsertedEvent))")
        print("MEMORY_RESIDENT: growth=\(formatBytes(mem.residentGrowthBytes)) bytes_per_event=\(String(format: "%.1f", mem.residentBytesPerInsertedEvent))")
        print("MAIN_THREAD: samples=\(mt.sampleCount) avg=\(String(format: "%.2f", mt.avgLatencyMs))ms p50=\(String(format: "%.2f", mt.p50LatencyMs))ms p95=\(String(format: "%.2f", mt.p95LatencyMs))ms p99=\(String(format: "%.2f", mt.p99LatencyMs))ms max=\(String(format: "%.2f", mt.maxStallMs))ms")
        print("FRAMES: dropped_60fps=\(mt.droppedFrames60fps) dropped_30fps=\(mt.droppedFrames30fps) dropped_100ms=\(mt.droppedFrames100ms)")

        let guardrail = PerformanceThresholds.guardrail
        let target = PerformanceThresholds.target

        // Guardrail pass/fail summary
        let p95Pass = mt.p95LatencyMs < guardrail.p95LatencyMs
        let p99Pass = mt.p99LatencyMs < guardrail.p99LatencyMs
        let stallPass = mt.maxStallMs < guardrail.maxStallMs
        let dropPercent = mt.sampleCount > 0 ? Double(mt.droppedFrames30fps) / Double(mt.sampleCount) * 100.0 : 0.0
        let dropPass = dropPercent < guardrail.maxDroppedFrames30fpsPercent
        let effectiveRatePercent = cfg.eventsPerSecond > 0 ? (pl.effectiveEventsPerSec / Double(cfg.eventsPerSecond)) * 100.0 : 0.0
        let ratePass = effectiveRatePercent >= guardrail.minEffectiveRatePercent
        let memoryPass = mem.residentBytesPerInsertedEvent < guardrail.maxResidentBytesPerInsertedEvent

        print("GUARDRAILS: p95<\(guardrail.p95LatencyMs)ms=\(p95Pass ? "PASS" : "FAIL") p99<\(guardrail.p99LatencyMs)ms=\(p99Pass ? "PASS" : "FAIL") max_stall<\(guardrail.maxStallMs)ms=\(stallPass ? "PASS" : "FAIL") 30fps_drops<\(guardrail.maxDroppedFrames30fpsPercent)%=\(dropPass ? "PASS" : "FAIL") eff_rate>=\(guardrail.minEffectiveRatePercent)%=\(ratePass ? "PASS" : "FAIL") resident_bytes_per_event<\(String(format: "%.0f", guardrail.maxResidentBytesPerInsertedEvent))=\(memoryPass ? "PASS" : "FAIL")")
        print("TARGET_REFERENCE: p95<\(target.p95LatencyMs)ms p99<\(target.p99LatencyMs)ms max_stall<\(target.maxStallMs)ms 30fps_drops<\(target.maxDroppedFrames30fpsPercent)% eff_rate>=\(target.minEffectiveRatePercent)% resident_bytes_per_event<\(String(format: "%.0f", target.maxResidentBytesPerInsertedEvent))")
        print("=== END STRESS TEST RESULTS ===")
    }

    private func formatBytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(value), countStyle: .memory)
    }

    private func requireFullStressSuite() throws {
        let env = ProcessInfo.processInfo.environment
        if env["STRESS_FULL_SUITE"] != "1" {
            throw XCTSkip("Set STRESS_FULL_SUITE=1 to run long-running stress scenarios")
        }
    }

    private func requireMemorySuite() throws {
        let env = ProcessInfo.processInfo.environment
        if env["STRESS_MEMORY_SUITE"] != "1" {
            throw XCTSkip("Set STRESS_MEMORY_SUITE=1 to run memory-growth stress scenarios")
        }
    }

    // MARK: - Fixture Resolution

    private func makeResultsPath(rate: Int, duration: Int) -> String {
        let testName = self.name.replacingOccurrences(of: "[^A-Za-z0-9_-]", with: "_", options: .regularExpression)
        let unique = UUID().uuidString
        return "/tmp/mac-monitor-stress-results-\(testName)-\(rate)x\(duration)-\(unique).json"
    }

    /// Resolves the fixture file path.
    ///
    /// Priority:
    /// 1. `STRESS_FIXTURE_PATH` environment variable (for CI/agent configuration)
    /// 2. `TestFixtures/stress-fixture.plist` relative to the project root
    /// 3. `nil` (StressTestRunner will try to use events from a live recording)
    private func resolveFixturePath() -> String? {
        // Check environment variable first
        if let envPath = ProcessInfo.processInfo.environment["STRESS_FIXTURE_PATH"],
           FileManager.default.fileExists(atPath: envPath) {
            return envPath
        }

        // Try to find fixture relative to the test source file
        // #filePath gives us the path to this source file at compile time
        let sourceDir = (String(#filePath) as NSString).deletingLastPathComponent
        let projectRoot = (sourceDir as NSString).deletingLastPathComponent
        let fixturePath = (projectRoot as NSString).appendingPathComponent("TestFixtures/stress-fixture.plist")

        if FileManager.default.fileExists(atPath: fixturePath) {
            return fixturePath
        }

        return nil
    }

    // MARK: - Error Types

    enum StressTestError: Error {
        case noResults
        case testFailed(String)
    }
}
