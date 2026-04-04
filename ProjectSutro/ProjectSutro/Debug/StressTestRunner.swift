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
            // Fall back to synthetic events so the test can run without a fixture
            // or a live recording session.
            Self.logger.warning("No real events available — generating synthetic template events for stress test")
            templateEvents = Self.makeSyntheticTemplateEvents(count: 100)
        }

        if templateEvents.isEmpty {
            Self.logger.error("Failed to generate synthetic template events. Cannot run stress test.")
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

    // MARK: - Synthetic Event Generation

    /// Generates synthetic `Message` values via JSON decoding for use when no
    /// fixture file or live recording is available.
    ///
    /// The events are structurally valid and exercise the full pipeline
    /// (MMAP append → index → filter → SwiftUI diff), but they use fabricated
    /// process metadata rather than real Endpoint Security events.
    ///
    /// - Parameter count: Number of distinct template events to generate.
    /// - Returns: An array of decoded `Message` values, or an empty array if decoding fails.
    static func makeSyntheticTemplateEvents(count: Int) -> [Message] {
        let now = Date()
        let decoder = JSONDecoder()
        // Message.message_darwin_time is a plain Date with synthesized Codable;
        // .secondsSince1970 matches what JSONDecoder reads from a Double value.
        decoder.dateDecodingStrategy = .secondsSince1970

        var events: [Message] = []
        events.reserveCapacity(count)

        let processNames = [
            "/usr/bin/xpcproxy", "/usr/libexec/xpcproxy", "/usr/bin/swift",
            "/usr/lib/dyld", "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "/usr/bin/mdworker_shared", "/usr/libexec/configd", "/usr/sbin/cfprefsd",
            "/usr/libexec/nsurlsessiond", "/System/Library/PrivateFrameworks/CoreTelephony.framework/Versions/A/Resources/coretelephonyd"
        ]
        let signingIDs = [
            "com.apple.xpcproxy", "com.apple.swift", "com.apple.finder",
            "com.apple.mdworker_shared", "com.apple.configd"
        ]

        for i in 0..<count {
            let pid = Int32(100 + i)
            let processName = processNames[i % processNames.count]
            let signingID = signingIDs[i % signingIDs.count]
            let ts = Int(now.timeIntervalSince1970)
            let tsSec = now.timeIntervalSince1970
            let timeString = ISO8601DateFormatter().string(from: now)

            let json = """
            {
                "id": "\(UUID().uuidString)",
                "version": 6,
                "schema_version": 1,
                "time": "\(timeString)",
                "mach_time": \(Int64(now.timeIntervalSince1970 * 1_000_000_000)),
                "message_darwin_time": \(tsSec),
                "macOS": "15.0",
                "sensor_id": "SYNTHETIC",
                "process": {
                    "id": "\(UUID().uuidString)",
                    "start_time": { "id": "\(UUID().uuidString)", "tv_sec": \(ts), "tv_usec": 0 },
                    "pid": \(pid),
                    "ppid": 1,
                    "original_ppid": 1,
                    "group_id": \(pid),
                    "session_id": 1,
                    "codesigning_flags": 570522369,
                    "signing_id": "\(signingID)",
                    "audit_token_string": "pid:\(pid), euid:0, ruid:0, rgid:0, egid:0, asid:100, auid:0, pidversion:1",
                    "responsible_audit_token_string": "pid:\(pid), euid:0, ruid:0, rgid:0, egid:0, asid:100, auid:0, pidversion:1",
                    "parent_audit_token_string": "pid:1, euid:0, ruid:0, rgid:0, egid:0, asid:100, auid:0, pidversion:1",
                    "executable": {
                        "id": "\(UUID().uuidString)",
                        "path": "\(processName)",
                        "path_truncated": false,
                        "stat": {
                            "id": "\(UUID().uuidString)",
                            "st_ino": \(Int64(1000 + i)),
                            "st_dev": 16777233,
                            "st_size": 65536,
                            "st_blocks": 128,
                            "st_blksize": 4096,
                            "st_flags": 0,
                            "st_gen": 0,
                            "st_mode": 33261,
                            "st_nlink": 1,
                            "st_uid": 0,
                            "st_gid": 0,
                            "st_rdev": 0,
                            "st_atimespec": { "id": "\(UUID().uuidString)", "tv_sec": \(ts), "tv_nsec": 0 },
                            "st_mtimespec": { "id": "\(UUID().uuidString)", "tv_sec": \(ts), "tv_nsec": 0 },
                            "st_ctimespec": { "id": "\(UUID().uuidString)", "tv_sec": \(ts), "tv_nsec": 0 },
                            "st_birthtimespec": { "id": "\(UUID().uuidString)", "tv_sec": \(ts), "tv_nsec": 0 }
                        }
                    },
                    "is_platform_binary": true,
                    "is_es_client": false,
                    "euid": 0,
                    "ruid": 0,
                    "euid_human": "root",
                    "ruid_human": "root",
                    "codesigning_type": "PLATFORM",
                    "file_quarantine_type": "DISABLED",
                    "is_adhoc_signed": false,
                    "get_task_allow": false,
                    "allow_jit": false,
                    "rootless": false,
                    "skip_lv": false
                },
                "thread": {
                    "id": "\(UUID().uuidString)",
                    "thread_id": \(Int64(i + 1))
                },
                "event": {
                    "exit": {
                        "id": "\(UUID().uuidString)",
                        "stat": 0
                    }
                },
                "event_type": 23,
                "es_event_type": "ES_EVENT_TYPE_NOTIFY_EXIT",
                "action_type": 1,
                "action_type_string": "ES_ACTION_TYPE_NOTIFY",
                "action": {}
            }
            """

            guard let data = json.data(using: .utf8),
                  let message = try? decoder.decode(Message.self, from: data) else {
                Self.logger.warning("Failed to decode synthetic event \(i)")
                continue
            }
            events.append(message)
        }

        return events
    }
}

#endif
