//
//  IndicatorAlertPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Notifications' cost
/// Times what notifications add to Mac Monitor's side of a recording: picking a batch's candidates on the XPC queue,
/// with and without hits, the coalescer's work per candidate, and a notice's text. Their budgets: 20 µs and 200 µs a
/// batch of 2,000 events, 1 µs a candidate, and 20 µs a notice.
final class IndicatorAlertPerformanceTests: PerformanceTestCase {
    /// Events in a batch, as the store's early save takes them.
    private static let batch = 2_000
    /// Batches per sample.
    private static let batches = 50

    /// A tap that delivers nowhere, with both switches on.
    private let tap: IndicatorAlertTap = {
        let tap = IndicatorAlertTap()
        tap.configure(IndicatorAlertSettings(high: true, medium: true), disabled: [], deliver: { _ in })
        return tap
    }()

    /// - Parameter hits: Each event's hits.
    /// - Returns: A batch of events.
    /// - Throws: The error making an event.
    private func batch(_ hits: [IndicatorHit]) throws -> [Message] {
        let message = try alertMessage(hits)
        return Array(repeating: message, count: Self.batch)
    }

    /// A batch of events that matched nothing: the common case.
    func testCandidatesWithoutHits() throws {
        let messages = try batch([])
        try benchmark("alerts.candidates.2000.none", unit: "batch", operations: Self.batches) {
            for _ in 0..<Self.batches where !tap.candidates(in: messages).isEmpty {
                throw BenchmarkFailure("A candidate from no hits")
            }
        }
    }

    /// A batch of events that each matched a Medium and two Lows.
    func testCandidatesWithHits() throws {
        let messages = try batch([alertHit("Ran a script", .low), alertHit("Mach-O written"), alertHit("Login", .low)])
        try benchmark("alerts.candidates.2000.hits", unit: "batch", operations: Self.batches) {
            for _ in 0..<Self.batches where tap.candidates(in: messages).count != Self.batch {
                throw BenchmarkFailure("A candidate missing")
            }
        }
    }

    /// Fourteen indicators' candidates, a hundred a second, through the coalescer.
    func testCoalescerObserve() throws {
        let events = try (0..<14).map { _ in try alertEvent(UUID()) }
        let count = 100_000
        try benchmark("alerts.coalescer.observe", unit: "candidate", operations: count) {
            var coalescer = IndicatorAlertCoalescer()
            var posted = 0
            for index in 0..<count {
                posted += coalescer.observe(events[index % events.count], now: Double(index) / 100).count
            }
            if posted == 0 { throw BenchmarkFailure("Nothing posted") }
        }
    }

    /// A first notice's text, from a candidate that matched other indicators.
    func testFirstNoticeContent() throws {
        let hits = [alertHit("Dylib inserted", .high), alertHit("Ran a script", .low), alertHit("Login", .low)]
        let event = try XCTUnwrap(IndicatorAlertPolicy.pick(try alertMessage(hits),
                                                            settings: IndicatorAlertSettings(high: true),
                                                            disabled: []))
        let (count, now, home) = (10_000, Date(), NSHomeDirectory())
        try benchmark("alerts.content.first", unit: "notice", operations: count) {
            for _ in 0..<count where IndicatorAlertContent(.first(event), now: now, home: home).title.isEmpty {
                throw BenchmarkFailure("No title")
            }
        }
    }
}
