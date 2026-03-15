//
//  MainThreadMonitor.swift
//  ProjectSutro
//
//  Measures main thread responsiveness by dispatching probe blocks
//  from a background timer and recording the latency (time between
//  dispatch and execution). When the main thread is blocked by
//  SwiftUI diffing or layout, latency spikes.
//
//  DEBUG ONLY — compiled out for release builds.
//

#if DEBUG

import Foundation
import OSLog

/// Structured results from a main thread monitoring session.
struct MainThreadMetrics: Codable {
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

/// Monitors main thread responsiveness by probing at ~120 Hz from a background timer.
///
/// Each probe dispatches a block to the main queue and records how long the main queue
/// takes to execute it. Under normal conditions this is sub-millisecond; when SwiftUI is
/// performing a large diff or layout pass, it spikes proportionally to the stall duration.
final class MainThreadMonitor {
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "MainThreadMonitor")

    private var timer: DispatchSourceTimer?
    private let probeQueue = DispatchQueue(label: "com.swiftlydetecting.agent.mainthread-monitor")

    /// Thread-safe sample storage (accessed only from probeQueue or after stop)
    private var samples: [Double] = []  // latencies in seconds
    private var isRunning = false

    /// Starts probing the main thread at ~120 Hz.
    func start() {
        probeQueue.async { [self] in
            guard !isRunning else { return }
            isRunning = true
            samples.removeAll()
            samples.reserveCapacity(4000)  // ~30s at 120Hz

            let timer = DispatchSource.makeTimerSource(queue: probeQueue)
            // ~120 Hz probes with 1ms leeway for timer coalescing
            timer.schedule(deadline: .now(), repeating: .milliseconds(8), leeway: .milliseconds(1))
            timer.setEventHandler { [weak self] in
                guard let self else { return }
                let dispatchTime = DispatchTime.now()
                DispatchQueue.main.async {
                    let arrivalTime = DispatchTime.now()
                    let latency = Double(arrivalTime.uptimeNanoseconds - dispatchTime.uptimeNanoseconds) / 1_000_000_000.0
                    self.probeQueue.async {
                        self.samples.append(latency)
                    }
                }
            }
            self.timer = timer
            timer.resume()
            Self.logger.info("Main thread monitor started (~120 Hz probes)")
        }
    }

    /// Stops probing and computes metrics from collected samples.
    ///
    /// - Returns: Computed metrics, or `nil` if no samples were collected.
    func stop() -> MainThreadMetrics? {
        return probeQueue.sync { [self] in
            guard isRunning else { return nil }
            isRunning = false
            timer?.cancel()
            timer = nil

            // Brief pause to let any in-flight main queue probes land
            // We process whatever we have — a few missed samples won't skew results
            let finalSamples = samples.sorted()
            guard !finalSamples.isEmpty else {
                Self.logger.warning("No samples collected")
                return nil
            }

            let count = finalSamples.count
            let avg = finalSamples.reduce(0, +) / Double(count)
            let p50 = percentile(sorted: finalSamples, p: 0.50)
            let p95 = percentile(sorted: finalSamples, p: 0.95)
            let p99 = percentile(sorted: finalSamples, p: 0.99)
            let maxStall = finalSamples.last ?? 0

            // Count dropped frames at various thresholds
            let threshold60fps = 1.0 / 60.0   // ~16.67ms
            let threshold30fps = 1.0 / 30.0   // ~33.33ms
            let threshold100ms = 0.1           // 100ms

            let dropped60 = finalSamples.filter { $0 > threshold60fps }.count
            let dropped30 = finalSamples.filter { $0 > threshold30fps }.count
            let dropped100 = finalSamples.filter { $0 > threshold100ms }.count

            let metrics = MainThreadMetrics(
                sampleCount: count,
                avgLatencyMs: avg * 1000.0,
                p50LatencyMs: p50 * 1000.0,
                p95LatencyMs: p95 * 1000.0,
                p99LatencyMs: p99 * 1000.0,
                maxStallMs: maxStall * 1000.0,
                droppedFrames60fps: dropped60,
                droppedFrames30fps: dropped30,
                droppedFrames100ms: dropped100
            )

            Self.logger.info("Main thread monitor stopped: \(count) samples, avg=\(String(format: "%.2f", metrics.avgLatencyMs))ms, p95=\(String(format: "%.2f", metrics.p95LatencyMs))ms, max=\(String(format: "%.2f", metrics.maxStallMs))ms")

            return metrics
        }
    }

    /// Computes the value at a given percentile from a pre-sorted array.
    private func percentile(sorted: [Double], p: Double) -> Double {
        guard !sorted.isEmpty else { return 0 }
        let index = p * Double(sorted.count - 1)
        let lower = Int(index)
        let upper = min(lower + 1, sorted.count - 1)
        let fraction = index - Double(lower)
        return sorted[lower] + fraction * (sorted[upper] - sorted[lower])
    }
}

#endif
