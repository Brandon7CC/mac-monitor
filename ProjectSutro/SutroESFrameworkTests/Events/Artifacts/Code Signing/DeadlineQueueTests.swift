//
//  DeadlineQueueTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Work with a deadline
/// Pins ``DeadlineQueue``: work that's done in time gives its result, work that blocks gives none at the deadline, and
/// while it's still blocked every run is refused without running, until it returns.
final class DeadlineQueueTests: XCTestCase {
    /// Work done in time gives its result, `nil` included.
    func testWorkInTime() {
        let queue = DeadlineQueue(label: "test.deadline", timeout: .seconds(5))
        XCTAssertEqual(queue.run { 42 }, 42)
        XCTAssertNil(queue.run { nil as Int? })
        XCTAssertFalse(queue.isStuck)
    }

    /// Work that blocks gives nothing at the deadline, and the caller doesn't wait for it. Until it returns, runs are
    /// refused at once and their work never runs. Once it has, runs run again.
    func testBlockedWorkIsAbandoned() {
        let queue = DeadlineQueue(label: "test.deadline", timeout: .milliseconds(100))
        let release = DispatchSemaphore(value: 0), returned = DispatchSemaphore(value: 0)
        let start = Date()
        XCTAssertNil(queue.run { () -> Int? in
            release.wait()
            returned.signal()
            return 1
        })
        XCTAssertLessThan(Date().timeIntervalSince(start), 5, "The caller waits only until the deadline")
        XCTAssertTrue(queue.isStuck)

        var ran = false
        XCTAssertNil(queue.run { () -> Int? in
            ran = true
            return 2
        })
        XCTAssertFalse(ran, "A run is refused while earlier work is stuck")

        release.signal()
        XCTAssertEqual(returned.wait(timeout: .now() + 5), .success)
        let unstuck = expectation(for: NSPredicate { _, _ in !queue.isStuck }, evaluatedWith: nil)
        wait(for: [unstuck], timeout: 5)
        XCTAssertEqual(queue.run { 3 }, 3)
    }
}
