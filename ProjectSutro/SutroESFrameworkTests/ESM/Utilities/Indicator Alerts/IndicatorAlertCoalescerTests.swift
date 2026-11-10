//
//  IndicatorAlertCoalescerTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Coalescing
/// Pins the coalescer's rules on an injected clock: an indicator's notice and its summaries, its windows, the Medium
/// and High tokens, the overflow summary's timing and order, and what it tracks.
final class IndicatorAlertCoalescerTests: XCTestCase {
    /// Limits with no Medium tokens, so every Medium goes to the overflow.
    private var noMediumTokens: IndicatorAlertLimits {
        var limits = IndicatorAlertLimits()
        limits.mediumBurst = 0
        return limits
    }

    /// - Parameter alerts: Posts.
    /// - Returns: Each one's kind: `first`, `summary` or `overflow`.
    private func kinds(_ alerts: [IndicatorAlert]) -> [String] {
        alerts.map {
            switch $0 {
            case .first: "first"
            case .summary: "summary"
            case .overflow: "overflow"
            }
        }
    }

    /// The first match posts at once. One within its window folds, and posts as a summary of one, with the latest
    /// event, exactly when the window ends.
    func testASecondMatchIsSummarizedWhenTheWindowEnds() throws {
        let id = UUID()
        let (first, second) = (try alertEvent(id), try alertEvent(id, path: "/bin/other"))
        var coalescer = IndicatorAlertCoalescer()
        XCTAssertEqual(coalescer.observe(first, now: 0), [.first(first)])
        XCTAssertNil(coalescer.nextDeadline, "A window with nothing in it needs no timer")
        XCTAssertEqual(coalescer.observe(second, now: 10), [])
        XCTAssertEqual(coalescer.nextDeadline, 60)
        XCTAssertEqual(coalescer.tick(now: 59.9), [])
        guard case .summary(let summary) = coalescer.tick(now: 60).first else { return XCTFail("No summary") }
        XCTAssertEqual(summary.count, 1)
        XCTAssertEqual(summary.latest, second)
        XCTAssertEqual(summary.processes, ["/bin/other"])
        XCTAssertNil(coalescer.nextDeadline)
    }

    /// A summary counts at most 16 distinct processes, a repeat never counting as more. Past them it says "or
    /// more". It runs from its earliest match's time, whatever order they came in, and opens its newest.
    func testASummaryCountsSixteenProcessesFromItsEarliestMatch() throws {
        let (id, base) = (UUID(), Date())
        var coalescer = IndicatorAlertCoalescer()
        _ = coalescer.observe(try alertEvent(id, time: base), now: 0)
        let times = (1...17).map { base.addingTimeInterval(Double($0)) }
        var folded = try times.enumerated().map { try alertEvent(id, time: $1, path: "/bin/p\($0)") }
        folded.swapAt(16, 8)
        folded.insert(try alertEvent(id, time: base.addingTimeInterval(-30), path: "/bin/p3"), at: 4)
        for (index, event) in folded.enumerated() { _ = coalescer.observe(event, now: 1 + Double(index)) }
        guard case .summary(let summary) = coalescer.tick(now: 60).first else { return XCTFail("No summary") }
        XCTAssertEqual(summary.count, 18)
        XCTAssertEqual(summary.processes.count, 16)
        XCTAssertTrue(summary.hasMoreProcesses)
        XCTAssertEqual(summary.since, base.addingTimeInterval(-30))
        XCTAssertEqual(summary.latest.time, times[16])
        XCTAssertTrue(IndicatorAlertContent(.summary(summary), now: base, home: "/Users/analyst").subtitle
            .hasSuffix("from 16 or more processes"))

        var sixteen = IndicatorAlertSummary(folded[0])
        for event in folded[1..<17] { sixteen.add(event, limit: 16) }
        XCTAssertEqual(sixteen.processes.count, 16)
        XCTAssertFalse(sixteen.hasMoreProcesses, "Sixteen distinct processes, one of them twice, are all counted")
    }

    /// While matches keep coming, windows run 60, 120, 240, 480, 900 and 900 seconds. After 900 seconds with none,
    /// the next notice's window is 60 again.
    func testWindowsDoubleToFifteenMinutesAndStartOverAfterQuiet() throws {
        let id = UUID()
        let event = try alertEvent(id)
        let run = ScenarioRun((0..<3000).map { ScenarioMatch(time: Double($0), key: 1, severity: .medium) }
                                + [ScenarioMatch(time: 5000, key: 1, severity: .medium),
                                   ScenarioMatch(time: 5001, key: 1, severity: .medium)],
                              keys: [id: 1], events: [1: event])
        XCTAssertEqual(run.posts, ["0.00:1:1", "60.00s:1:59", "180.00s:1:120", "420.00s:1:240", "900.00s:1:480",
                                   "1800.00s:1:900", "2700.00s:1:900", "3600.00s:1:300", "5000.00:1:1",
                                   "5060.00s:1:1"])
    }

    /// A window that ends with nothing in it leaves the indicator idle with the same length: its next notice's
    /// window is as long.
    func testAWindowThatEndsEmptyKeepsItsLength() throws {
        let id = UUID()
        let event = try alertEvent(id)
        let times: [TimeInterval] = [0, 10, 200, 210]
        let run = ScenarioRun(times.map { ScenarioMatch(time: $0, key: 1, severity: .medium) },
                              keys: [id: 1], events: [1: event])
        XCTAssertEqual(run.posts, ["0.00:1:1", "60.00s:1:1", "200.00:1:1", "320.00s:1:1"])
    }

    /// Three Medium notices may post at once, then one every two minutes. The rest go to the overflow.
    func testMediumTokensBurstThreeThenComeBackEveryTwoMinutes() throws {
        var coalescer = IndicatorAlertCoalescer()
        let events = try (0..<6).map { _ in try alertEvent(UUID()) }
        XCTAssertEqual(kinds(events.prefix(4).flatMap { coalescer.observe($0, now: 0) }),
                       ["first", "first", "first"])
        XCTAssertEqual(kinds(coalescer.observe(events[4], now: 60)), ["overflow"],
                       "The fourth's overflow, and half a token: the fifth goes to the next")
        XCTAssertEqual(kinds(coalescer.observe(events[5], now: 120)), ["overflow", "first"])
    }

    /// A Medium summary needs two tokens and takes one, so one is kept for a first notice: with one and a half
    /// there, the summary moves to the overflow, and its window still doubles.
    func testAMediumSummaryNeedsTwoTokens() throws {
        let (id, other) = (UUID(), UUID())
        var coalescer = IndicatorAlertCoalescer()
        _ = coalescer.observe(try alertEvent(id), now: 0)
        _ = coalescer.observe(try alertEvent(other), now: 0)
        _ = coalescer.observe(try alertEvent(id), now: 1)
        XCTAssertEqual(coalescer.tick(now: 60), [], "1.5 tokens: the summary may not take the last one")
        XCTAssertEqual(coalescer.overflow.entries[id]?.count, 1)
        XCTAssertEqual(coalescer.slots[id]?.length, 120)
        XCTAssertEqual(kinds(coalescer.observe(try alertEvent(UUID()), now: 60)), ["first"],
                       "The token kept is a new indicator's")
    }

    /// High has tokens of its own: with Medium's spent, five Highs post at once, and a sixth waits for the next
    /// token, 30 seconds on, as a notice of its own, never in the overflow.
    func testHighHasTokensOfItsOwn() throws {
        var coalescer = IndicatorAlertCoalescer(limits: noMediumTokens)
        _ = coalescer.observe(try alertEvent(UUID()), now: 0)
        let highs = try (0..<6).map { _ in try alertEvent(UUID(), .high) }
        XCTAssertEqual(highs.flatMap { coalescer.observe($0, now: 0) }, highs.prefix(5).map(IndicatorAlert.first))
        XCTAssertEqual(coalescer.nextDeadline, 0 + 10, "The overflow's gather comes first")
        XCTAssertEqual(kinds(coalescer.tick(now: 10)), ["overflow"])
        XCTAssertEqual(coalescer.nextDeadline, 30)
        XCTAssertEqual(coalescer.tick(now: 30), [.first(highs[5])])
        XCTAssertTrue(coalescer.overflow.isEmpty)
    }

    /// The overflow gathers for 10 seconds, then posts at most every 60, 120, 240, 480 and 900 seconds while it keeps
    /// filling, and starts over at 60 once an interval passes with nothing in it.
    func testTheOverflowBacksOffAndStartsOver() throws {
        var matches = stride(from: 0.0, to: 1900, by: 5).map { ScenarioMatch(time: $0, key: 1, severity: .medium) }
        matches += [3611, 3622].map { ScenarioMatch(time: $0, key: 1, severity: .medium) }
        let id = UUID()
        let run = ScenarioRun(matches, keys: [id: 1], events: [1: try alertEvent(id)], limits: noMediumTokens)
        XCTAssertEqual(run.alerts.map(\.time), [10, 70, 190, 430, 910, 1810, 2710, 3621, 3681])
        XCTAssertEqual(run.covered, matches.count)
    }

    /// The overflow lists the indicators with the fewest matches first, then by name.
    func testTheOverflowListsTheRarestFirst() throws {
        var coalescer = IndicatorAlertCoalescer(limits: noMediumTokens)
        let counts = ["Mach-O written": 24, "Launch job loaded": 2, "Adhoc or unsigned": 2, "Dylib inserted": 1]
        for (name, count) in counts {
            let event = try alertEvent(UUID(), name: name)
            for _ in 0..<count { _ = coalescer.observe(event, now: 1) }
        }
        guard case .overflow(let overflow) = coalescer.tick(now: 11).first else { return XCTFail("No overflow") }
        XCTAssertEqual(overflow.entries.map(\.indicator.name),
                       ["Dylib inserted", "Adhoc or unsigned", "Launch job loaded", "Mach-O written"])
        XCTAssertEqual(overflow.count, 29)
    }

    /// A Medium event older than two minutes goes only to the overflow. A High that old still posts.
    func testOldMediumsOnlyGoToTheOverflow() throws {
        var coalescer = IndicatorAlertCoalescer()
        let (medium, high) = (try alertEvent(UUID()), try alertEvent(UUID(), .high))
        XCTAssertEqual(coalescer.observe(medium, now: 0, age: 121), [])
        XCTAssertEqual(coalescer.observe(high, now: 0, age: 600), [.first(high)])
        XCTAssertEqual(kinds(coalescer.observe(try alertEvent(UUID()), now: 0, age: 120)), ["first"])
        XCTAssertEqual(coalescer.overflow.entries[medium.indicator.id]?.count, 1)
    }

    /// Past 256 indicators, the one matched least recently is forgotten.
    func testTrackingForgetsTheLeastRecentlyMatched() throws {
        var coalescer = IndicatorAlertCoalescer(limits: noMediumTokens)
        let ids = (0..<257).map { _ in UUID() }
        for (index, id) in ids.enumerated() { _ = coalescer.observe(try alertEvent(id), now: Double(index)) }
        XCTAssertEqual(coalescer.slots.count, 256)
        XCTAssertNil(coalescer.slots[ids[0]])
        XCTAssertNotNil(coalescer.slots[ids[1]])
    }

    /// An indicator forgotten while it has matches waiting moves them to the overflow: none is lost.
    func testForgettingAWaitingIndicatorKeepsItsMatches() throws {
        var limits = IndicatorAlertLimits()
        limits.trackedIndicators = 2
        var coalescer = IndicatorAlertCoalescer(limits: limits)
        let events = try (0..<3).map { _ in try alertEvent(UUID()) }
        for (index, event) in events.enumerated() {
            _ = coalescer.observe(event, now: Double(index))
            _ = coalescer.observe(event, now: Double(index) + 0.5)
        }
        XCTAssertEqual(coalescer.slots.count, 2)
        XCTAssertNil(coalescer.slots[events[0].indicator.id])
        XCTAssertEqual(coalescer.overflow.entries[events[0].indicator.id]?.count, 1)
    }

    /// No deadline while idle. Otherwise the earliest of a window's end and the overflow's.
    func testTheNextDeadlineIsTheEarliestDue() throws {
        var coalescer = IndicatorAlertCoalescer()
        XCTAssertNil(coalescer.nextDeadline)
        let event = try alertEvent(UUID())
        _ = coalescer.observe(event, now: 0)
        _ = coalescer.observe(event, now: 5)
        XCTAssertEqual(coalescer.nextDeadline, 60)
        _ = coalescer.observe(try alertEvent(UUID()), now: 20, age: 600)
        XCTAssertEqual(coalescer.nextDeadline, 30, "The overflow's gather ends first")
    }

    /// Dropping an indicator forgets what it gathered: nothing posts for it later.
    func testDroppingForgetsAnIndicatorsMatches() throws {
        var coalescer = IndicatorAlertCoalescer()
        let event = try alertEvent(UUID())
        _ = coalescer.observe(event, now: 0)
        _ = coalescer.observe(event, now: 5)
        _ = coalescer.observe(try alertEvent(UUID()), now: 5, age: 600)
        coalescer.drop { _, severity in severity == .medium }
        XCTAssertNil(coalescer.nextDeadline)
        XCTAssertEqual(coalescer.tick(now: 1000), [])
    }
}
