//
//  ESLoggerTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - eslogger format rules
/// Pins the rules in ``ESLogger`` that make Mac Monitor's `time` and hashes match `eslogger(1)`'s, and how times are
/// read back from a trace.
final class ESLoggerTests: XCTestCase {
    /// 2026-10-04T00:01:54Z, in seconds since 1970.
    private static let seconds = 1_791_072_114
    
    /// A value of type `T` made of `bytes`, such as an `es_cdhash_t` (a C array, imported as a tuple).
    ///
    /// - Parameters:
    ///   - type: The type to make.
    ///   - bytes: Its bytes, exactly `MemoryLayout<T>.size` of them.
    /// - Returns: The value.
    private func value<T>(of type: T.Type, bytes: [UInt8]) -> T {
        precondition(bytes.count == MemoryLayout<T>.size, "\(T.self) takes \(MemoryLayout<T>.size) bytes")
        return bytes.withUnsafeBytes { $0.load(as: T.self) }
    }
    
    // MARK: time from a timespec
    
    /// Every `time` has eslogger's shape, which is how ``ESLogger/time(_:darwinTime:)`` recognizes one.
    func testTimeFromTimespecHasEsloggersShape() {
        XCTAssertTrue(ESLogger.isESLoggerTime(ESLogger.time(timespec(tv_sec: Self.seconds, tv_nsec: 999_999_999))))
    }
    
    // MARK: Recognizing eslogger's time
    
    /// eslogger's `time` is recognized by its shape: UTC, with nine fractional digits.
    func testIsESLoggerTime() {
        XCTAssertTrue(ESLogger.isESLoggerTime("2026-10-04T00:01:54.394127173Z"))
        XCTAssertTrue(ESLogger.isESLoggerTime("1969-12-31T23:59:59.999999000Z"))
    }
    
    /// Anything else isn't: 2.1's local time, another separator or zone, a non-digit, or another length.
    func testOtherTimesAreNotESLoggerTimes() {
        for time in ["2026-10-03T17:01:54.394Z", "2026-10-04T00:01:54.394127173+", "2026-10-04 00:01:54.394127173Z",
                     "2026-10-04T00:01:54.39412717aZ", "2026-10-04T00:01:54.3941271730Z",
                     "2026-10-04T00:01:54.39412717Z", String(repeating: "x", count: 30), ""] {
            XCTAssertFalse(ESLogger.isESLoggerTime(time), time)
        }
    }
    
    // MARK: Hex
    
    // MARK: Fallback to message_darwin_time
    
    /// A `time`, its message's `message_darwin_time`, and the `time` exported, with what the case pins.
    private static let times: [(label: String, time: String, darwinTime: Date, expected: String)] = [
        ("A time already in eslogger's format is kept as it is, even when message_darwin_time disagrees",
         "2026-10-04T00:01:54.394127173Z", Date(timeIntervalSince1970: 0), "2026-10-04T00:01:54.394127173Z"),
        ("Only eslogger's shape is kept: 30 characters of anything else are rebuilt like any other time",
         String(repeating: "x", count: 30), Date(timeIntervalSince1970: TimeInterval(seconds)),
         "2026-10-04T00:01:54.000000000Z"),
        ("A Security Extension older than 3.0.0 sent local time to the millisecond: it's rebuilt from "
         + "message_darwin_time", "2026-10-03T17:01:54.500Z", Date(timeIntervalSince1970: TimeInterval(seconds) + 0.5),
         "2026-10-04T00:01:54.500000000Z"),
        ("An empty time is rebuilt from message_darwin_time", "",
         Date(timeIntervalSince1970: TimeInterval(seconds) + 0.5), "2026-10-04T00:01:54.500000000Z"),
        ("The rebuilt time is rounded to the microsecond: a millisecond stays one", "2026-10-03T17:01:54.394Z",
         Date(timeIntervalSince1970: 1_791_072_114.394), "2026-10-04T00:01:54.394000000Z"),
        ("The rebuilt time is rounded to the microsecond, which drops the error of Date's Double instead of printing "
         + "it as nanoseconds the time never had", "2026-10-03T17:01:54.394Z",
         Date(timeIntervalSince1970: 1_791_072_114.394127173), "2026-10-04T00:01:54.394127000Z"),
        ("A fraction that rounds up to a whole second carries into the second", "",
         Date(timeIntervalSince1970: 1_791_072_114.9999996), "2026-10-04T00:01:55.000000000Z"),
        ("A time before 1970 counts its fraction up from the second before", "", Date(timeIntervalSince1970: -0.5),
         "1969-12-31T23:59:59.500000000Z"),
        ("A microsecond before 1970 counts up from the second before", "", Date(timeIntervalSince1970: -0.000001),
         "1969-12-31T23:59:59.999999000Z"),
        ("A message_darwin_time too far from 1970 to fit in an Int of seconds leaves time as it is",
         "2026-10-03T17:01:54.394Z", Date(timeIntervalSince1970: 1e19), "2026-10-03T17:01:54.394Z"),
        ("A message_darwin_time of 1e300 leaves time as it is", "2026-10-03T17:01:54.394Z",
         Date(timeIntervalSinceReferenceDate: 1e300), "2026-10-03T17:01:54.394Z"),
        ("An infinite message_darwin_time leaves time as it is", "2026-10-03T17:01:54.394Z",
         Date(timeIntervalSinceReferenceDate: .infinity), "2026-10-03T17:01:54.394Z"),
        ("A NaN message_darwin_time leaves time as it is", "2026-10-03T17:01:54.394Z",
         Date(timeIntervalSinceReferenceDate: .nan), "2026-10-03T17:01:54.394Z"),
    ]
    
    /// Each row of ``times`` exports its `time`.
    func testTime() {
        for (label, time, darwinTime, expected) in Self.times {
            XCTAssertEqual(ESLogger.time(time, darwinTime: darwinTime), expected, label)
        }
    }
    
    /// A 2.1 time read as local time and rebuilt is eslogger's UTC time of the same instant, whatever this Mac's time
    /// zone, and reads back as that instant.
    func testLegacyTimeRoundTrip() throws {
        let legacy = "2026-10-03T17:01:54.394Z"
        let date = try XCTUnwrap(ESLogger.date(fromTime: legacy, legacy: true))
        let time = ESLogger.time(legacy, darwinTime: date)
        XCTAssertTrue(ESLogger.isESLoggerTime(time), time)
        XCTAssertTrue(time.hasSuffix(".394000000Z"), time)
        let read = try XCTUnwrap(ESLogger.date(fromTime: time, legacy: false))
        XCTAssertEqual(read.timeIntervalSince1970, date.timeIntervalSince1970, accuracy: 1e-6)
    }
    
    // MARK: Reading times back
    
    /// eslogger's `time` is read exactly, to the nanosecond.
    func testUTCTimespecReadsNanoseconds() throws {
        let time = try XCTUnwrap(ESLogger.utcTimespec(from: "2026-10-04T00:01:54.394127173Z"))
        XCTAssertEqual(time.tv_sec, Self.seconds)
        XCTAssertEqual(time.tv_nsec, 394_127_173)
    }
    
    /// Shorter fractions (``TimeVal/humanFormat()``'s six digits) and none at all are read too.
    func testUTCTimespecReadsShorterFractions() throws {
        let microseconds = try XCTUnwrap(ESLogger.utcTimespec(from: "2026-10-04T00:01:54.123456Z"))
        XCTAssertEqual(microseconds.tv_sec, Self.seconds)
        XCTAssertEqual(microseconds.tv_nsec, 123_456_000)
        let whole = try XCTUnwrap(ESLogger.utcTimespec(from: "2026-10-04T00:01:54Z"))
        XCTAssertEqual(whole.tv_sec, Self.seconds)
        XCTAssertEqual(whole.tv_nsec, 0)
    }
    
    /// Text that isn't a UTC time in that format is not one.
    func testUTCTimespecRejectsOtherText() {
        for text in ["", "not a time", "2026-10-04T00:01:54.Z", "2026-13-04T00:01:54Z", "2026-10-04 00:01:54Z",
                     "2026-10-04T00:01:54.394127173+00:00", "2026-10-04T00:01:54.1234567890Z"] {
            XCTAssertNil(ESLogger.utcTimespec(from: text), text)
        }
    }
    
    /// An eslogger `time` is the same instant as its timespec.
    func testDateFromEsloggerTime() throws {
        let date = try XCTUnwrap(ESLogger.date(fromTime: "2026-10-04T00:01:54.394127173Z", legacy: false))
        let expected = timespec(tv_sec: Self.seconds, tv_nsec: 394_127_173)
        XCTAssertEqual(date, ProcessHelpers.timespecToTimestamp(timespec: expected))
    }
    
    /// A `time` of 2.1's shape from Mac Monitor 2.1.0 or older is local time, read with the formatter that wrote it.
    func testDateFromLegacyTimeIsLocalTime() throws {
        let written = Date(timeIntervalSince1970: 1_791_072_119.285)
        let time = ProcessHelpers.timestampFormatter.string(from: written)
        XCTAssertEqual(time.utf8.count, 24)
        let read = try XCTUnwrap(ESLogger.date(fromTime: time, legacy: true))
        XCTAssertEqual(read.timeIntervalSince1970, written.timeIntervalSince1970, accuracy: 0.001)
    }
    
    /// The same shape from eslogger (not legacy) is UTC, and eslogger's `time` is never read as local time, even in a
    /// record that could come from Mac Monitor 2.1.
    func testDateFromUTCTime() throws {
        for (time, legacy, seconds) in [("2026-10-04T00:01:59.285Z", false, 1_791_072_119.285),
                                        ("2026-10-04T00:01:54.394127173Z", true, 1_791_072_114.394127173)] {
            let read = try XCTUnwrap(ESLogger.date(fromTime: time, legacy: legacy), time)
            XCTAssertEqual(read.timeIntervalSince1970, seconds, accuracy: 1e-6, time)
        }
    }
    
    /// Text that isn't a time has no date, legacy or not.
    func testDateFromTextThatIsNoTime() {
        XCTAssertNil(ESLogger.date(fromTime: "", legacy: false))
        XCTAssertNil(ESLogger.date(fromTime: "", legacy: true))
        XCTAssertNil(ESLogger.date(fromTime: "not a time, but 24 chars", legacy: true))
    }
}
