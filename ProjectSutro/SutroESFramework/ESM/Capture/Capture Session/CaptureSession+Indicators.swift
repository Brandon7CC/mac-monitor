//
//  CaptureSession+Indicators.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Indicators
extension CaptureSession {
    /// Evaluate a new set of indicators on every lane from the next message on, or none. An event already being built
    /// keeps the set it was admitted with, so each event is judged entirely by the old set or entirely by the new one.
    ///
    /// Each event a lane builds is stamped with the indicators it matches (``Message/indicators``) before it's encoded
    /// or held, so an app exec held for Launch Services carries its verdicts. Events a lane never builds (left out by a
    /// field filter, skipped while not recording) are never evaluated.
    ///
    /// - Parameter indicators: The set, or `nil` to evaluate nothing, so events carry no verdicts.
    /// - Returns: `false` after ``stop()``, with nothing changed.
    @discardableResult
    public func applyIndicators(_ indicators: CompiledIndicators?) -> Bool {
        guard !isStopped else { return false }
        self.indicators = indicators
        lanes.forEach { $0.setIndicators(indicators) }
        Self.logger.log("""
            \(self.label, privacy: .public): evaluating \(Self.describe(indicators), privacy: .public).
            """)
        return true
    }

    /// A set as the log names it.
    ///
    /// - Parameter indicators: The set, or `nil`.
    /// - Returns: Such as "27 indicators (1 can't run)", or "no indicators".
    static func describe(_ indicators: CompiledIndicators?) -> String {
        guard let indicators else { return "no indicators" }
        let problems = indicators.problems.count
        return "\(indicators.count) indicators" + (problems > 0 ? " (\(problems) can't run)" : "")
    }
}


// MARK: - A lane's indicator state
/// What one capture lane keeps to evaluate indicators: the values its events are read into (``MessageValueCache``),
/// allocated once, and the counts it last gave the lane's counters.
///
/// **Threading:** the lane's own. Only the thread holding the lane's gate uses it.
final class LaneIndicators {
    /// The lane's values, reset for each event.
    private var values = MessageValueCache()
    /// The counts last taken (``takeCounts()``).
    private var reported = IndicatorCounts()

    /// Stamp an event with the indicators it matches, as its record lists them
    /// (``CompiledIndicators/stamp(_:values:)``).
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - indicators: The set the event was admitted with. `nil` leaves the event without verdicts.
    func stamp(_ message: inout Message, with indicators: CompiledIndicators?) {
        indicators?.stamp(&message, values: &values)
    }

    /// The lane's counts, when they changed since they were last taken, so the lane only takes its counters' lock
    /// for an event that changed them.
    ///
    /// - Returns: The counts over the lane's lifetime, or `nil` when they're as last taken.
    func takeCounts() -> IndicatorCounts? {
        let counts = IndicatorCounts(hitCapped: UInt64(values.cappedEvents),
                                     truncated: UInt64(values.truncatedEvaluations),
                                     exhausted: UInt64(values.scanExhaustedEvents),
                                     undetermined: UInt64(values.undeterminedEvents))
        guard counts != reported else { return nil }
        reported = counts
        return counts
    }
}


/// A capture lane's indicator counts, over its lifetime.
struct IndicatorCounts: Equatable {
    /// Events that matched more indicators than a record lists (``CompiledIndicators/hitLimit``).
    var hitCapped: UInt64 = 0
    /// Values Foundation compared only part of (``MessageValueCache/truncatedEvaluations``).
    var truncated: UInt64 = 0
    /// Events whose indicator scan budget ran out somewhere (``MessageValueCache/scanExhaustedEvents``).
    var exhausted: UInt64 = 0
    /// Events with indicators left undetermined (``MessageValueCache/undeterminedEvents``).
    var undetermined: UInt64 = 0
}
