//
//  ESLoggerUTCTimeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - UTC times by arithmetic
/// Pins that ``ESLogger/utcTime(seconds:fraction:digits:)`` writes exactly what the `ISO8601FormatStyle` path wrote
/// before it, and that ``ESLogger/time(_:)``, ``TimeSpec/humanFormat()`` and ``TimeVal/humanFormat()`` still write
/// that for every time, inside its range or not.
final class ESLoggerUTCTimeTests: XCTestCase {
    /// 9999-12-31T23:59:59Z, the last second written by arithmetic.
    private static let lastSecond = 253_402_300_799
    
    /// A time as `TimeSpec` and `TimeVal` formatted it before: the whole second with `ISO8601FormatStyle`, then the
    /// fraction zero-padded in place of the `Z`.
    ///
    /// - Parameters:
    ///   - seconds: Seconds since 1970.
    ///   - fraction: The fraction of a second.
    ///   - digits: 9 for nanoseconds, 6 for microseconds.
    /// - Returns: The formatted time.
    private func formatted(seconds: Int, fraction: Int, digits: Int) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(seconds))
        let padded = String(format: digits == 9 ? "%09d" : "%06d", fraction)
        return date.formatted(Date.ISO8601FormatStyle()).replacingOccurrences(of: "Z", with: ".\(padded)Z")
    }
    
    /// Check every way of formatting one time against the formatter.
    ///
    /// - Parameters:
    ///   - seconds: Seconds since 1970.
    ///   - nanoseconds: The fraction for a `timespec`.
    ///   - microseconds: The fraction for a `timeval`.
    ///   - line: The caller's line, for failures.
    private func assertMatches(seconds: Int, nanoseconds: Int, microseconds: Int, line: UInt = #line) {
        let spec = timespec(tv_sec: seconds, tv_nsec: nanoseconds)
        let expected = formatted(seconds: seconds, fraction: nanoseconds, digits: 9)
        XCTAssertEqual(ESLogger.time(spec), expected, line: line)
        XCTAssertEqual(TimeSpec(from: spec).humanFormat(), expected, line: line)
        let value = timeval(tv_sec: seconds, tv_usec: Int32(microseconds))
        let expectedMicroseconds = formatted(seconds: seconds, fraction: microseconds, digits: 6)
        XCTAssertEqual(TimeVal(from: value).humanFormat(), expectedMicroseconds, line: line)
    }
    
    /// The epoch, ends of days, leap days, century years, the last four-digit second, and the fractions' ends.
    func testEdgeTimesMatchTheFormatter() {
        let seconds = [0, 1, 59, 60, 3_599, 3_600, 86_399, 86_400, 68_169_600, 951_782_400, 951_868_799, 978_307_200,
                       1_791_072_114, 4_107_542_400, 4_102_444_799, 253_402_214_400, Self.lastSecond]
        let fractions = [(0, 0), (1, 1), (5, 5), (394_127_173, 394_127), (999_999_999, 999_999)]
        for second in seconds {
            for (nanoseconds, microseconds) in fractions {
                assertMatches(seconds: second, nanoseconds: nanoseconds, microseconds: microseconds)
            }
        }
    }
    
    /// Random times from 1970 through 9999.
    func testRandomTimesMatchTheFormatter() {
        for _ in 0..<5_000 {
            assertMatches(seconds: Int.random(in: 0...Self.lastSecond), nanoseconds: Int.random(in: 0..<1_000_000_000),
                          microseconds: Int.random(in: 0..<1_000_000))
        }
    }
    
    /// Every day of a leap year and of the years around it, at midnight and just before the next.
    func testEveryDayMatchesTheFormatter() {
        let start = 946_684_800 // 2000-01-01T00:00:00Z
        for day in 0..<(366 + 365 * 2) {
            assertMatches(seconds: start + day * 86_400, nanoseconds: 0, microseconds: 0)
            assertMatches(seconds: start + day * 86_400 + 86_399, nanoseconds: 999_999_999, microseconds: 999_999)
        }
    }
    
    /// Before 1970, after 9999, and fractions that aren't one are left to the formatter, which writes them as before.
    func testOutOfRangeFallsBackToTheFormatter() {
        XCTAssertNil(ESLogger.utcTime(seconds: -1, fraction: 0, digits: 9))
        XCTAssertNil(ESLogger.utcTime(seconds: Self.lastSecond + 1, fraction: 0, digits: 9))
        XCTAssertNil(ESLogger.utcTime(seconds: 0, fraction: -1, digits: 9))
        XCTAssertNil(ESLogger.utcTime(seconds: 0, fraction: 1_000_000_000, digits: 9))
        XCTAssertNil(ESLogger.utcTime(seconds: 0, fraction: 1_000_000, digits: 6))
        for seconds in [-1, -86_400, -2_208_988_800] {
            assertMatches(seconds: seconds, nanoseconds: 5, microseconds: 5)
        }
        let spec = timespec(tv_sec: 1_791_072_114, tv_nsec: 1_000_000_000)
        XCTAssertEqual(ESLogger.time(spec), formatted(seconds: spec.tv_sec, fraction: spec.tv_nsec, digits: 9))
        let value = timeval(tv_sec: 1_791_072_114, tv_usec: 1_000_000)
        XCTAssertEqual(TimeVal(from: value).humanFormat(), formatted(seconds: 1_791_072_114, fraction: 1_000_000,
                                                                     digits: 6))
    }
}
