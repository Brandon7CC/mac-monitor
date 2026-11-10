//
//  IndicatorAlertSchedulerTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Scheduling notifications
/// Pins the scheduler's timer on short windows: a notice posts as its batch arrives, a summary when its window ends
/// with no further call, an old Medium only in the overflow, and nothing for an indicator dropped.
final class IndicatorAlertSchedulerTests: XCTestCase {
    /// Windows and the overflow's gather of a tenth of a second.
    private var quick: IndicatorAlertLimits {
        var limits = IndicatorAlertLimits()
        (limits.firstWindow, limits.overflowGather) = (0.1, 0.1)
        return limits
    }

    /// What a scheduler posted.
    private let posted = Recorded<IndicatorAlert>()

    /// - Returns: A scheduler on short windows that records what it posts.
    private func scheduler() -> IndicatorAlertScheduler {
        let posted = posted
        return IndicatorAlertScheduler(limits: quick, label: "test.indicator-alerts", leeway: .milliseconds(1)) {
            $0.forEach(posted.append)
        }
    }

    /// A notice posts with its batch, and the match after it posts as a summary once the window ends, on the timer.
    func testTheTimerPostsTheSummary() throws {
        let scheduler = scheduler()
        let id = UUID()
        let (first, second) = (try alertEvent(id), try alertEvent(id))
        scheduler.receive([first, second])
        scheduler.sync()
        XCTAssertEqual(posted.all, [.first(first)])
        XCTAssertTrue(waitUntil { self.posted.all.count == 2 })
        guard case .summary(let summary) = posted.all.last else { return XCTFail("No summary") }
        XCTAssertEqual(summary.latest, second)
    }

    /// An old Medium goes only to the overflow, which the timer posts after its gather.
    func testAnOldMediumPostsInTheOverflow() throws {
        let scheduler = scheduler()
        let old = try alertEvent(UUID(), time: Date().addingTimeInterval(-600))
        scheduler.receive([old])
        scheduler.sync()
        XCTAssertEqual(posted.all, [])
        XCTAssertTrue(waitUntil { !self.posted.all.isEmpty })
        guard case .overflow(let overflow) = posted.all.first else { return XCTFail("No overflow") }
        XCTAssertEqual(overflow.entries.map(\.latest), [old])
    }

    /// An indicator dropped before its window ends posts no summary.
    func testADroppedIndicatorPostsNothingMore() throws {
        let scheduler = scheduler()
        let event = try alertEvent(UUID())
        scheduler.receive([event, event])
        scheduler.drop { id, _ in id == event.indicator.id }
        scheduler.sync()
        Thread.sleep(forTimeInterval: 0.3)
        scheduler.sync()
        XCTAssertEqual(posted.all, [.first(event)])
    }
}
