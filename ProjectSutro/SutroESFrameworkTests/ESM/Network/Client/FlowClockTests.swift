//
//  FlowClockTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The clocks
/// Pins how a descriptor's `mach_continuous_time` ticks become a record's times, in `Int64` throughout: a tick count
/// after the sample, one from before more sleep than the Mac had uptime, and 0, none of which may trap.
final class FlowClockTests: XCTestCase {
    /// 9 s up, 1 s of it asleep, ticks in nanoseconds.
    private let clock = FlowClock(continuous: 10_000_000_000, absolute: 9_000_000_000,
                                  wall: 1_764_000_000_000_000_000, numer: 1, denom: 1)

    /// Ticks after the sample, from a datagram queued during the read, are just after it.
    func testTicksAfterTheSample() {
        let time = clock.time(ofTicks: 10_000_000_500)
        XCTAssertEqual(time, FlowTime(machTime: 9_000_000_500, wall: 1_764_000_000_000_000_500))
    }

    /// Ticks from before more sleep than their own uptime clamp `mach_time` to 0, and the wall time is still right.
    func testTicksBeforeTheSleep() {
        let clock = FlowClock(continuous: 30_000_000_000, absolute: 2_000_000_000, wall: 1_764_000_000_000_000_000,
                              numer: 1, denom: 1)
        let time = clock.time(ofTicks: 1_000_000_000)
        XCTAssertEqual(time.machTime, 0)
        XCTAssertEqual(time.wall, 1_764_000_000_000_000_000 - 29_000_000_000)
    }

    /// 0 ticks is the sample's own moment.
    func testZeroTicksIsTheSample() {
        XCTAssertEqual(clock.time(ofTicks: 0), FlowTime(machTime: 9_000_000_000, wall: 1_764_000_000_000_000_000))
    }

    /// No tick count traps, on Apple silicon's timebase either, and the sample is read from the system as one.
    func testNoTickCountTraps() {
        let silicon = FlowClock(continuous: 240_000_000, absolute: 24_000_000, wall: 1_764_000_000_000_000_000,
                                numer: 125, denom: 3)
        XCTAssertEqual(silicon.time(ofTicks: 240_000_024).wall, 1_764_000_000_000_000_000 + 1_000)
        XCTAssertEqual(silicon.seconds, 10, accuracy: 1e-9)
        for ticks in [UInt64.max, UInt64(Int64.max), 1, 1 << 62] {
            _ = silicon.time(ofTicks: ticks)
            _ = clock.time(ofTicks: ticks)
        }
        let now = FlowClock.now()
        XCTAssertLessThanOrEqual(now.absolute, now.continuous)
        XCTAssertEqual(Double(now.wall) / 1e9, Date().timeIntervalSince1970, accuracy: 5)
        XCTAssertEqual(Double(now.time(ofTicks: 0).machTime), Double(now.absolute))
    }
}
