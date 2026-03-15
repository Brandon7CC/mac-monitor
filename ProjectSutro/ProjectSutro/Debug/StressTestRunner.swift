//
//  StressTestRunner.swift
//  ProjectSutro
//
//  Orchestrates automated stress tests for the full UI event pipeline.
//
//  When launched with `--stress-test`, this class:
//  1. Parses configuration from command-line arguments
//  2. Loads template events from a fixture file (or generates synthetic ones)
//  3. Clears the EventStore for a clean baseline
//  4. Starts a MainThreadMonitor to measure UI responsiveness
//  5. Injects events at a configurable rate via EventStore.insertEvents()
//     (this triggers the FULL pipeline: publish -> onChange -> filter -> @State -> SwiftUI diff)
//  6. After the configured duration, stops and writes structured JSON results
//
//  DEBUG ONLY — compiled out for release builds.
//

#if DEBUG

import Foundation
import SutroESFramework
import OSLog

/// Configuration parsed from command-line arguments.
struct StressTestConfig {
    /// Events per second injection rate
    let eventsPerSecond: Int
    /// Total test duration in seconds
    let durationSeconds: Int
    /// Path to fixture plist file (optional — generates synthetic events if nil)
    let fixturePath: String?
    /// Path to write JSON results
    let resultsPath: String

    /// Parses config from CommandLine.arguments.
    ///
    /// Expected arguments:
    /// - `--stress-test` (presence flag, already checked by caller)
    /// - `--stress-rate <N>` (events/sec, default 5000)
    /// - `--stress-duration <N>` (seconds, default 30)
    /// - `--stress-fixture <path>` (optional fixture plist path)
    /// - `--stress-results <path>` (required results output path)
    static func fromCommandLine() -> StressTestConfig? {
        let args = CommandLine.arguments

        guard args.contains("--stress-test") else { return nil }

        func argValue(_ flag: String) -> String? {
            guard let idx = args.firstIndex(of: flag), idx + 1 < args.count else { return nil }
            return args[idx + 1]
        }

        let rate = argValue("--stress-rate").flatMap(Int.init) ?? 5000
        let duration = argValue("--stress-duration").flatMap(Int.init) ?? 30
        let fixture = argValue("--stress-fixture")
        let results = argValue("--stress-results") ?? "/tmp/mac-monitor-stress-results.json"

        return StressTestConfig(
            eventsPerSecond: rate,
            durationSeconds: duration,
            fixturePath: fixture,
            resultsPath: results
        )
    }
}

/// Structured JSON output written after a stress test completes.
struct StressTestResults: Codable {
    let config: ConfigOutput
    let mainThread: MainThreadMetrics
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
        /// Memory footprint (bytes) at injection start.
        let startPhysicalFootprintBytes: UInt64
        /// Peak memory footprint (bytes) observed during the run.
        let peakPhysicalFootprintBytes: UInt64
        /// Memory footprint (bytes) when the run completes.
        let endPhysicalFootprintBytes: UInt64
        /// Peak growth relative to start (bytes), including mapped file growth.
        let totalGrowthBytes: UInt64
        /// Peak growth normalized by inserted events, including mapped file growth.
        let totalBytesPerInsertedEvent: Double
        /// MMAP allocated bytes at start.
        let startMappedAllocatedBytes: UInt64
        /// MMAP allocated bytes at end.
        let endMappedAllocatedBytes: UInt64
        /// Growth in MMAP allocated bytes.
        let mappedAllocatedGrowthBytes: UInt64
        /// Growth in MMAP allocated bytes per inserted event.
        let mappedAllocatedBytesPerInsertedEvent: Double
        /// MMAP used bytes at start.
        let startMappedUsedBytes: UInt64
        /// MMAP used bytes at end.
        let endMappedUsedBytes: UInt64
        /// Growth in MMAP used bytes.
        let mappedUsedGrowthBytes: UInt64
        /// Growth in MMAP used bytes per inserted event.
        let mappedUsedBytesPerInsertedEvent: Double
        /// Peak growth with mapped-used growth removed.
        let residentGrowthBytes: UInt64
        /// Peak resident growth normalized by inserted events.
        let residentBytesPerInsertedEvent: Double
    }
}

/// Orchestrates the stress test lifecycle.
final class StressTestRunner {
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "StressTestRunner")

    /// Self-retaining reference to keep the runner alive during async execution.
    private static var activeRunner: StressTestRunner?

    private let config: StressTestConfig
    private let monitor = MainThreadMonitor()
    private var injectionTimer: DispatchSourceTimer?
    private var memorySampleTimer: DispatchSourceTimer?
    private let injectionQueue = DispatchQueue(label: "com.swiftlydetecting.agent.stress-injection")

    /// Template events to clone and inject. Loaded from fixture or the current EventStore.
    private var templateEvents: [Message] = []

    /// Tracking
    private var totalEventsInserted: Int = 0
    private var testStartTime: Date?
    private var startPhysicalFootprintBytes: UInt64 = 0
    private var peakPhysicalFootprintBytes: UInt64 = 0
    private var startMappedAllocatedBytes: UInt64 = 0
    private var startMappedUsedBytes: UInt64 = 0
    private var peakResidentGrowthBytes: UInt64 = 0

    init(config: StressTestConfig) {
        self.config = config
    }

    /// Starts the stress test. Call from the main thread after UI has settled.
    func run() {
        Self.activeRunner = self
        Self.logger.info("Stress test starting: rate=\(self.config.eventsPerSecond)/s, duration=\(self.config.durationSeconds)s")

        // Load template events
        if let fixturePath = config.fixturePath {
            let url = URL(fileURLWithPath: fixturePath)
            templateEvents = FixtureCapture.loadFixture(from: url)
        }

        if templateEvents.isEmpty {
            // Try loading from current EventStore as fallback
            let snapshot = EventStore.shared.getIndexSnapshot()
            if !snapshot.isEmpty {
                let indices = Array(0..<min(1000, snapshot.count))
                templateEvents = EventStore.shared.getEventsWindow(indices)
            }
        }

        if templateEvents.isEmpty {
            Self.logger.error("No template events available for stress test. Provide a fixture file with --stress-fixture or start a recording first.")
            writeEmptyResults(error: "No template events available")
            Self.activeRunner = nil
            return
        }

        Self.logger.info("Loaded \(self.templateEvents.count) template events")

        // Clear EventStore for clean baseline
        EventStore.shared.clearEvents()

        // Brief delay to let the clear propagate through the pipeline
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [self] in
            startInjection()
        }
    }

    private func startInjection() {
        // Start monitoring main thread
        monitor.start()
        testStartTime = Date()
        totalEventsInserted = 0

        // Capture memory baseline and begin sampling while stress test runs.
        let baseline = currentPhysicalFootprintBytes() ?? 0
        startPhysicalFootprintBytes = baseline
        peakPhysicalFootprintBytes = baseline
        let mmapBaseline = EventStore.shared.getMMapFootprintBytes()
        startMappedAllocatedBytes = mmapBaseline.allocated
        startMappedUsedBytes = mmapBaseline.used
        peakResidentGrowthBytes = 0
        startMemorySampling()

        // Calculate batch parameters
        // We inject in batches at a fixed interval to achieve the target rate.
        // Using 20Hz injection (50ms interval) to match EventStore's publish coalesce window.
        let injectionHz = 20.0
        let batchSize = max(1, config.eventsPerSecond / Int(injectionHz))
        let intervalMs = Int(1000.0 / injectionHz)

        Self.logger.info("Injection: \(batchSize) events every \(intervalMs)ms (target: \(self.config.eventsPerSecond)/s)")

        let timer = DispatchSource.makeTimerSource(queue: injectionQueue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(intervalMs), leeway: .milliseconds(2))

        let templateCount = templateEvents.count
        var templateIndex = 0

        timer.setEventHandler { [weak self] in
            guard let self else { return }

            // Build a batch by cycling through template events with fresh UUIDs and timestamps
            var batch: [Message] = []
            batch.reserveCapacity(batchSize)

            for _ in 0..<batchSize {
                var event = self.templateEvents[templateIndex % templateCount]
                // Give each event a unique ID so SwiftUI sees it as distinct
                event.id = UUID()
                // Update timestamp so incremental filter treats it as "new"
                event.message_darwin_time = Date()
                batch.append(event)
                templateIndex += 1
            }

            // This triggers the FULL pipeline:
            // insertEvents -> MMAP append -> index -> schedulePublish -> eventCount
            // -> onChange -> scheduleFilterUpdate -> executeFilterUpdate -> @State assignment
            // -> SwiftUI diff -> render
            EventStore.shared.insertEvents(batch)
            self.totalEventsInserted += batchSize
        }

        injectionTimer = timer
        timer.resume()

        // Schedule stop after duration
        DispatchQueue.main.asyncAfter(deadline: .now() + Double(config.durationSeconds)) { [self] in
            stopAndReport()
        }
    }

    private func stopAndReport() {
        // Stop injection
        injectionTimer?.cancel()
        injectionTimer = nil

        // Stop memory sampling and capture final snapshot.
        memorySampleTimer?.cancel()
        memorySampleTimer = nil

        let endPhysicalFootprintBytes = currentPhysicalFootprintBytes() ?? peakPhysicalFootprintBytes
        let peakPhysicalFootprintBytes = max(self.peakPhysicalFootprintBytes, endPhysicalFootprintBytes)
        let growthBytes = peakPhysicalFootprintBytes >= startPhysicalFootprintBytes
            ? peakPhysicalFootprintBytes - startPhysicalFootprintBytes
            : 0
        let bytesPerInsertedEvent = totalEventsInserted > 0
            ? Double(growthBytes) / Double(totalEventsInserted)
            : 0

        let mmapEnd = EventStore.shared.getMMapFootprintBytes()
        let endMappedAllocatedBytes = mmapEnd.allocated
        let endMappedUsedBytes = mmapEnd.used
        let mappedAllocatedGrowthBytes = endMappedAllocatedBytes >= startMappedAllocatedBytes
            ? endMappedAllocatedBytes - startMappedAllocatedBytes
            : 0
        let mappedUsedGrowthBytes = endMappedUsedBytes >= startMappedUsedBytes
            ? endMappedUsedBytes - startMappedUsedBytes
            : 0
        let mappedAllocatedBytesPerInsertedEvent = totalEventsInserted > 0
            ? Double(mappedAllocatedGrowthBytes) / Double(totalEventsInserted)
            : 0
        let mappedUsedBytesPerInsertedEvent = totalEventsInserted > 0
            ? Double(mappedUsedGrowthBytes) / Double(totalEventsInserted)
            : 0

        let aggregateResidentGrowthBytes = growthBytes > mappedUsedGrowthBytes
            ? growthBytes - mappedUsedGrowthBytes
            : 0
        let residentGrowthBytes = max(peakResidentGrowthBytes, aggregateResidentGrowthBytes)
        let residentBytesPerInsertedEvent = totalEventsInserted > 0
            ? Double(residentGrowthBytes) / Double(totalEventsInserted)
            : 0

        let endTime = Date()
        let actualDuration = testStartTime.map { endTime.timeIntervalSince($0) } ?? 0

        // Brief delay to let final pipeline flushes complete before stopping the monitor
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [self] in
            // Stop monitoring and collect metrics
            guard let metrics = monitor.stop() else {
                Self.logger.error("Failed to collect main thread metrics")
                writeEmptyResults(error: "No metrics collected")
                Self.activeRunner = nil
                return
            }

            let results = StressTestResults(
                config: .init(
                    eventsPerSecond: config.eventsPerSecond,
                    durationSeconds: config.durationSeconds,
                    fixtureEventCount: templateEvents.count
                ),
                mainThread: metrics,
                pipeline: .init(
                    totalEventsInserted: totalEventsInserted,
                    actualDurationSec: actualDuration,
                    effectiveEventsPerSec: actualDuration > 0 ? Double(totalEventsInserted) / actualDuration : 0
                ),
                memory: .init(
                    startPhysicalFootprintBytes: startPhysicalFootprintBytes,
                    peakPhysicalFootprintBytes: peakPhysicalFootprintBytes,
                    endPhysicalFootprintBytes: endPhysicalFootprintBytes,
                    totalGrowthBytes: growthBytes,
                    totalBytesPerInsertedEvent: bytesPerInsertedEvent,
                    startMappedAllocatedBytes: startMappedAllocatedBytes,
                    endMappedAllocatedBytes: endMappedAllocatedBytes,
                    mappedAllocatedGrowthBytes: mappedAllocatedGrowthBytes,
                    mappedAllocatedBytesPerInsertedEvent: mappedAllocatedBytesPerInsertedEvent,
                    startMappedUsedBytes: startMappedUsedBytes,
                    endMappedUsedBytes: endMappedUsedBytes,
                    mappedUsedGrowthBytes: mappedUsedGrowthBytes,
                    mappedUsedBytesPerInsertedEvent: mappedUsedBytesPerInsertedEvent,
                    residentGrowthBytes: residentGrowthBytes,
                    residentBytesPerInsertedEvent: residentBytesPerInsertedEvent
                )
            )

            writeResults(results)
            Self.logger.info("Stress test complete: \(self.totalEventsInserted) events in \(String(format: "%.1f", actualDuration))s")
            Self.activeRunner = nil
        }
    }

    private func writeResults(_ results: StressTestResults) {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(results)
            let url = URL(fileURLWithPath: config.resultsPath)
            try data.write(to: url, options: .atomic)
            Self.logger.info("Results written to \(self.config.resultsPath)")
        } catch {
            Self.logger.error("Failed to write results: \(error)")
        }
    }

    private func startMemorySampling() {
        let timer = DispatchSource.makeTimerSource(queue: injectionQueue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(250), leeway: .milliseconds(20))
        timer.setEventHandler { [weak self] in
            guard let self,
                  let current = self.currentPhysicalFootprintBytes() else { return }
            if current > self.peakPhysicalFootprintBytes {
                self.peakPhysicalFootprintBytes = current
            }

            let currentGrowth = current >= self.startPhysicalFootprintBytes
                ? current - self.startPhysicalFootprintBytes
                : 0
            let mappedUsedNow = EventStore.shared.getMMapFootprintBytes().used
            let mappedUsedGrowthNow = mappedUsedNow >= self.startMappedUsedBytes
                ? mappedUsedNow - self.startMappedUsedBytes
                : 0
            let residentGrowthNow = currentGrowth > mappedUsedGrowthNow
                ? currentGrowth - mappedUsedGrowthNow
                : 0
            if residentGrowthNow > self.peakResidentGrowthBytes {
                self.peakResidentGrowthBytes = residentGrowthNow
            }
        }
        memorySampleTimer = timer
        timer.resume()
    }

    private func currentPhysicalFootprintBytes() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.stride / MemoryLayout<natural_t>.stride)

        let kerr: kern_return_t = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), intPtr, &count)
            }
        }

        guard kerr == KERN_SUCCESS else { return nil }
        return info.phys_footprint
    }

    private func writeEmptyResults(error: String) {
        // Write a minimal JSON indicating failure
        let errorJSON = """
        {
            "error": "\(error)"
        }
        """
        do {
            let url = URL(fileURLWithPath: config.resultsPath)
            try errorJSON.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            Self.logger.error("Failed to write error results: \(error)")
        }
    }
}

#endif
