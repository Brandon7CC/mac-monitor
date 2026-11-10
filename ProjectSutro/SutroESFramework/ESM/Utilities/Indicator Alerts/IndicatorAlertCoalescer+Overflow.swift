//
//  IndicatorAlertCoalescer+Overflow.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - The overflow summary
extension IndicatorAlertCoalescer {
    /// The overflow summary's matches and timing. It gathers for ``IndicatorAlertLimits/overflowGather`` after its
    /// first match lands while it's empty, posts no sooner than an interval after the last one, and doubles that
    /// interval each time it posts, up to ``IndicatorAlertLimits/overflowMaxInterval``. Once an interval passes with
    /// it empty, the interval starts over. It takes no token.
    struct OverflowState: Sendable {
        /// Each indicator's matches, by identity.
        private(set) var entries: [UUID: IndicatorAlertOverflow.Entry] = [:]
        /// When it posts, while it holds matches.
        private(set) var due = TimeInterval.infinity
        /// The soonest it may post again.
        private var next = -TimeInterval.infinity
        /// The interval after its next post.
        private(set) var interval: TimeInterval

        /// - Parameter interval: Its first interval.
        init(interval: TimeInterval) {
            self.interval = interval
        }

        /// Does it hold no match?
        var isEmpty: Bool { entries.isEmpty }

        /// Gather an indicator's matches.
        ///
        /// - Parameters:
        ///   - indicator: The indicator.
        ///   - count: Its matches.
        ///   - latest: The latest of them.
        ///   - now: The clock now.
        ///   - limits: The numbers it follows.
        mutating func add(_ indicator: IndicatorAlertEvent.Match, count: Int, latest: IndicatorAlertEvent,
                          now: TimeInterval, limits: IndicatorAlertLimits) {
            if entries.isEmpty {
                if now >= next { interval = limits.overflowFirstInterval }
                due = max(now + limits.overflowGather, next)
            }
            guard var entry = entries[indicator.id] else {
                entries[indicator.id] = .init(indicator: indicator, count: count, latest: latest)
                return
            }
            entry.count += count
            if latest.time >= entry.latest.time { entry.latest = latest }
            entries[indicator.id] = entry
        }

        /// The summary, if it's due, emptying it.
        ///
        /// - Parameters:
        ///   - now: The clock now.
        ///   - limits: The numbers it follows.
        /// - Returns: The summary, or `nil` when it's empty or not due.
        mutating func take(now: TimeInterval, limits: IndicatorAlertLimits) -> IndicatorAlertOverflow? {
            guard !entries.isEmpty, now >= due else { return nil }
            let summary = IndicatorAlertOverflow(Array(entries.values))
            (entries, due) = ([:], .infinity)
            next = now + interval
            interval = min(interval * 2, limits.overflowMaxInterval)
            return summary
        }

        /// Forget some indicators' matches.
        ///
        /// - Parameter shouldDrop: Given an indicator, should its matches be forgotten?
        mutating func drop(where shouldDrop: (IndicatorAlertEvent.Match) -> Bool) {
            entries = entries.filter { !shouldDrop($0.value.indicator) }
            if entries.isEmpty { due = .infinity }
        }
    }
}
