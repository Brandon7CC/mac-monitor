//
//  StopWatchdogTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Stop watchdog
/// Pins ``StopWatchdog``, which ends a `macmonitor stream` whose stop the Security Extension doesn't answer: not
/// before its deadline, then with 128 plus the signal's number.
final class StopWatchdogTests: XCTestCase {
    /// The deadline the tests use: long enough to see nothing has exited yet.
    private static let deadline: DispatchTimeInterval = .milliseconds(300)

    /// Armed for Ctrl-C, it exits 130 at its deadline, and only once.
    func testItExitsAtItsDeadlineWith128PlusTheSignal() {
        let statuses = OSAllocatedUnfairLock<[Int32]>(initialState: [])
        StopWatchdog(deadline: Self.deadline) { status in statuses.withLock { $0.append(status) } }
            .arm(for: SIGINT)
        usleep(100_000)
        XCTAssertEqual(statuses.withLock { $0 }, [], "It exited before its deadline")
        XCTAssertTrue(waitUntil(timeout: 2) { !statuses.withLock { $0 }.isEmpty }, "It never exited")
        usleep(100_000)
        XCTAssertEqual(statuses.withLock { $0 }, [128 + SIGINT])
    }

    /// `kill` and a closed terminal get their own statuses: 143 and 129.
    func testEachSignalHasItsOwnStatus() {
        let statuses = OSAllocatedUnfairLock<Set<Int32>>(initialState: [])
        let watchdog = StopWatchdog(deadline: .milliseconds(10)) { status in
            statuses.withLock { _ = $0.insert(status) }
        }
        watchdog.arm(for: SIGTERM)
        watchdog.arm(for: SIGHUP)
        XCTAssertTrue(waitUntil(timeout: 2) { statuses.withLock { $0.count } == 2 }, "\(statuses.withLock { $0 })")
        XCTAssertEqual(statuses.withLock { $0 }, [128 + SIGTERM, 128 + SIGHUP])
    }

    /// A stream's stop gets 3 seconds: one more than ``StreamCommand/stop(timeout:)`` waits for the Security
    /// Extension's answer.
    func testAStopGetsThreeSeconds() {
        XCTAssertEqual(StopWatchdog().deadline, .seconds(3))
    }
}
