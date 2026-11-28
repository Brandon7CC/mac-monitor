//
//  FileScanBudget.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/24/26.
//

import Foundation


// MARK: - The scanner's share of the CPU
/// How much CPU the scanner may spend, as a token bucket of CPU seconds, and how long a scan is expected to take.
///
/// The Security Extension stays under 10% of one core, so the scanner gets a share of that: by default 5% on average
/// (``refillPerSecond``), with up to one CPU second saved up for a burst (``capacity``), such as a download that
/// writes a few large binaries at once. A scan is charged the CPU time it actually took. A file is only admitted when
/// the bucket holds its expected cost, and when it would finish within the hold's window behind the files already
/// waiting. Otherwise it's left unscanned, and its record says why (``YaraScan/overBudget``, ``YaraScan/busy``).
///
/// The expected cost is the file's size times a running average of CPU seconds per byte, which starts at 7 ms per MB
/// (about what Apple's rules cost on the macOS 13 and 27 VMs) and follows what scans really take.
///
/// **Threading:** not thread-safe. ``FileScanner`` keeps it under its lock.
struct FileScanBudget {
    /// CPU seconds added each second: the scanner's average share of one core.
    let refillPerSecond: Double
    /// The most CPU seconds saved up.
    let capacity: Double
    /// The latest a scan may be expected to finish, in seconds from now, counting the scans queued before it.
    let window: TimeInterval
    /// The CPU seconds saved up now.
    private(set) var tokens: Double
    /// The running average cost of a byte, in CPU seconds.
    private(set) var secondsPerByte: Double
    /// The expected cost of the scans admitted and not yet finished.
    private(set) var queued: Double = 0
    /// When the bucket was last refilled, in seconds on ``clock``.
    private var refilled: TimeInterval
    /// The clock: seconds since boot unless a test gives another.
    private let clock: () -> TimeInterval

    /// The weight a new scan's cost gets in the running average.
    static let smoothing = 0.2
    /// The cost a byte starts at: 7 ms per MB.
    static let startingSecondsPerByte = 0.007 / Double(1 << 20)
    /// The least a scan is expected to cost: reading and scanning even a small file takes about 0.1 ms.
    static let minimumCost = 0.0001

    /// - Parameters:
    ///   - refillPerSecond: CPU seconds added each second.
    ///   - capacity: The most CPU seconds saved up. The bucket starts full.
    ///   - window: The latest a scan may be expected to finish.
    ///   - clock: The clock.
    init(refillPerSecond: Double = 0.05, capacity: Double = 1.0, window: TimeInterval = 0.4,
         clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.refillPerSecond = refillPerSecond
        self.capacity = capacity
        self.window = window
        self.clock = clock
        tokens = capacity
        secondsPerByte = Self.startingSecondsPerByte
        refilled = clock()
    }

    /// What the budget says of a file.
    enum Admission: Equatable {
        /// Scan it, at this expected cost in CPU seconds.
        case admit(cost: Double)
        /// The bucket doesn't hold its cost.
        case overBudget
        /// It wouldn't finish within the window behind the scans already queued.
        case busy
    }

    /// The expected cost of scanning a number of bytes.
    ///
    /// - Parameter bytes: The file's size.
    /// - Returns: CPU seconds.
    func cost(of bytes: Int) -> Double {
        max(Self.minimumCost, Double(bytes) * secondsPerByte)
    }

    /// Decide whether to scan a file, and count its cost as queued when it's admitted.
    ///
    /// - Parameter bytes: The file's size.
    /// - Returns: The decision.
    mutating func admit(bytes: Int) -> Admission {
        refill()
        let cost = cost(of: bytes)
        guard cost <= tokens - queued else { return .overBudget }
        guard queued + cost <= window else { return .busy }
        queued += cost
        return .admit(cost: cost)
    }

    /// Charge a finished scan what it really cost, and learn from it.
    ///
    /// - Parameters:
    ///   - expected: The cost it was admitted at.
    ///   - spent: The CPU seconds it took.
    ///   - bytes: The bytes it scanned. 0 learns nothing, as for a file that wasn't read.
    mutating func charge(expected: Double, spent: Double, bytes: Int) {
        refill()
        queued = max(0, queued - expected)
        tokens = max(-capacity, tokens - spent)
        guard bytes >= 1 << 16 else { return }
        let observed = spent / Double(bytes)
        secondsPerByte += Self.smoothing * (observed - secondsPerByte)
    }

    /// Add the tokens earned since the last refill, up to the capacity.
    private mutating func refill() {
        let now = clock()
        tokens = min(capacity, tokens + max(0, now - refilled) * refillPerSecond)
        refilled = now
    }
}
