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
    
    /// `time` is UTC with nine fractional digits, as eslogger writes it.
    func testTimeFromTimespecIsUTCWithNanoseconds() {
        XCTAssertEqual(ESLogger.time(timespec(tv_sec: Self.seconds, tv_nsec: 394_127_173)),
                       "2026-10-04T00:01:54.394127173Z")
    }
    
    /// Small fractions are zero-padded to nine digits, and a whole second still has them.
    func testTimeFromTimespecPadsTheFraction() {
        XCTAssertEqual(ESLogger.time(timespec(tv_sec: Self.seconds, tv_nsec: 5)), "2026-10-04T00:01:54.000000005Z")
        XCTAssertEqual(ESLogger.time(timespec(tv_sec: 0, tv_nsec: 0)), "1970-01-01T00:00:00.000000000Z")
    }
    
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
    
    /// Hashes are two uppercase hex digits per byte, as eslogger writes them.
    func testHexIsUppercaseTwoDigitsPerByte() {
        XCTAssertEqual(ESLogger.hex((UInt8(0x00), UInt8(0x0F), UInt8(0xAB), UInt8(0xFF))), "000FABFF")
    }
    
    /// A code directory hash is 40 uppercase hex digits.
    func testCDHashIsUppercaseHex() {
        let bytes: [UInt8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                              0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67]
        let cdhash = value(of: es_cdhash_t.self, bytes: bytes)
        XCTAssertEqual(cdhashToString(cdhash: cdhash), "00112233445566778899AABBCCDDEEFF01234567")
    }
    
    /// A SHA-256 digest is 64 uppercase hex digits.
    func testSHA256IsUppercaseHex() {
        let digest = value(of: es_sha256_t.self, bytes: (0..<32).map { UInt8($0 * 8 + 7) })
        let hex = sha256HexString(digest)
        XCTAssertEqual(hex.count, 64)
        XCTAssertEqual(hex, hex.uppercased())
        XCTAssertTrue(hex.hasPrefix("070F171F272F373F"))
        XCTAssertTrue(hex.hasSuffix("EFF7FF"))
    }
    
    // MARK: Fallback to message_darwin_time
    
    /// A `time` already in eslogger's format is kept as it is, even when `message_darwin_time` disagrees.
    func testEsloggerTimeIsKept() {
        let time = "2026-10-04T00:01:54.394127173Z"
        XCTAssertEqual(ESLogger.time(time, darwinTime: Date(timeIntervalSince1970: 0)), time)
    }
    
    /// Only eslogger's shape is kept: 30 characters of anything else are rebuilt like any other time.
    func testOnlyEsloggersShapeIsKept() {
        let time = String(repeating: "x", count: 30)
        XCTAssertEqual(ESLogger.time(time, darwinTime: Date(timeIntervalSince1970: TimeInterval(Self.seconds))),
                       "2026-10-04T00:01:54.000000000Z")
    }
    
    /// A Security Extension older than 2.2.0 sent local time to the millisecond: it's rebuilt from
    /// `message_darwin_time`.
    func testLegacyTimeIsRebuiltFromDarwinTime() {
        let darwinTime = Date(timeIntervalSince1970: TimeInterval(Self.seconds) + 0.5)
        XCTAssertEqual(ESLogger.time("2026-10-03T17:01:54.500Z", darwinTime: darwinTime),
                       "2026-10-04T00:01:54.500000000Z")
        XCTAssertEqual(ESLogger.time("", darwinTime: darwinTime), "2026-10-04T00:01:54.500000000Z")
    }
    
    /// The rebuilt time is rounded to the microsecond, which drops the error of `Date`'s `Double` (seconds since 2001)
    /// instead of printing it as nanoseconds the time never had.
    func testRebuiltTimeIsRoundedToTheMicrosecond() {
        let millisecond = Date(timeIntervalSince1970: 1_791_072_114.394)
        XCTAssertEqual(ESLogger.time("2026-10-03T17:01:54.394Z", darwinTime: millisecond),
                       "2026-10-04T00:01:54.394000000Z")
        let nanosecond = Date(timeIntervalSince1970: 1_791_072_114.394127173)
        XCTAssertEqual(ESLogger.time("2026-10-03T17:01:54.394Z", darwinTime: nanosecond),
                       "2026-10-04T00:01:54.394127000Z")
    }
    
    /// A fraction that rounds up to a whole second carries into the second.
    func testRebuiltTimeRoundsIntoTheNextSecond() {
        XCTAssertEqual(ESLogger.time("", darwinTime: Date(timeIntervalSince1970: 1_791_072_114.9999996)),
                       "2026-10-04T00:01:55.000000000Z")
    }
    
    /// A time before 1970 counts its fraction up from the second before.
    func testRebuiltTimeBefore1970() {
        XCTAssertEqual(ESLogger.time("", darwinTime: Date(timeIntervalSince1970: -0.5)),
                       "1969-12-31T23:59:59.500000000Z")
        XCTAssertEqual(ESLogger.time("", darwinTime: Date(timeIntervalSince1970: -0.000001)),
                       "1969-12-31T23:59:59.999999000Z")
    }
    
    /// A 2.1 time read as local time and rebuilt is eslogger's UTC time of the same instant, whatever this Mac's time
    /// zone, and reads back as that instant.
    ///
    /// - Throws: An `XCTest` failure if a time isn't read.
    func testLegacyTimeRoundTrip() throws {
        let legacy = "2026-10-03T17:01:54.394Z"
        let date = try XCTUnwrap(ESLogger.date(fromTime: legacy, legacy: true))
        let time = ESLogger.time(legacy, darwinTime: date)
        XCTAssertTrue(ESLogger.isESLoggerTime(time), time)
        XCTAssertTrue(time.hasSuffix(".394000000Z"), time)
        let read = try XCTUnwrap(ESLogger.date(fromTime: time, legacy: false))
        XCTAssertEqual(read.timeIntervalSince1970, date.timeIntervalSince1970, accuracy: 1e-6)
    }
    
    /// A `message_darwin_time` too far from 1970 to fit in an `Int` of seconds leaves `time` as it is.
    func testDarwinTimeThatIsNoTimeKeepsTime() {
        let time = "2026-10-03T17:01:54.394Z"
        XCTAssertEqual(ESLogger.time(time, darwinTime: Date(timeIntervalSince1970: 1e19)), time)
        XCTAssertEqual(ESLogger.time(time, darwinTime: Date(timeIntervalSinceReferenceDate: 1e300)), time)
        XCTAssertEqual(ESLogger.time(time, darwinTime: Date(timeIntervalSinceReferenceDate: .infinity)), time)
        XCTAssertEqual(ESLogger.time(time, darwinTime: Date(timeIntervalSinceReferenceDate: .nan)), time)
    }
    
    // MARK: Reading times back
    
    /// eslogger's `time` is read exactly, to the nanosecond.
    ///
    /// - Throws: An `XCTest` failure if a time isn't read.
    func testUTCTimespecReadsNanoseconds() throws {
        let time = try XCTUnwrap(ESLogger.utcTimespec(from: "2026-10-04T00:01:54.394127173Z"))
        XCTAssertEqual(time.tv_sec, Self.seconds)
        XCTAssertEqual(time.tv_nsec, 394_127_173)
    }
    
    /// Shorter fractions (``TimeVal/humanFormat()``'s six digits) and none at all are read too.
    ///
    /// - Throws: An `XCTest` failure if a time isn't read.
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
    ///
    /// - Throws: An `XCTest` failure if a time isn't read.
    func testDateFromEsloggerTime() throws {
        let date = try XCTUnwrap(ESLogger.date(fromTime: "2026-10-04T00:01:54.394127173Z", legacy: false))
        let expected = timespec(tv_sec: Self.seconds, tv_nsec: 394_127_173)
        XCTAssertEqual(date, ProcessHelpers.timespecToTimestamp(timespec: expected))
    }
    
    /// A `time` of 2.1's shape from Mac Monitor 2.1.0 or older is local time, read with the formatter that wrote it.
    ///
    /// - Throws: An `XCTest` failure if a time isn't read.
    func testDateFromLegacyTimeIsLocalTime() throws {
        let written = Date(timeIntervalSince1970: 1_791_072_119.285)
        let time = ProcessHelpers.timestampFormatter.string(from: written)
        XCTAssertEqual(time.utf8.count, 24)
        let read = try XCTUnwrap(ESLogger.date(fromTime: time, legacy: true))
        XCTAssertEqual(read.timeIntervalSince1970, written.timeIntervalSince1970, accuracy: 0.001)
    }
    
    /// The same shape from eslogger (not legacy) is UTC.
    ///
    /// - Throws: An `XCTest` failure if a time isn't read.
    func testDateFromShortTimeIsUTCWhenNotLegacy() throws {
        let read = try XCTUnwrap(ESLogger.date(fromTime: "2026-10-04T00:01:59.285Z", legacy: false))
        XCTAssertEqual(read.timeIntervalSince1970, 1_791_072_119.285, accuracy: 1e-6)
    }
    
    /// eslogger's `time` is never read as local time, even in a record that could come from Mac Monitor 2.1.
    ///
    /// - Throws: An `XCTest` failure if a time isn't read.
    func testDateFromEsloggerTimeIsUTCWhenLegacy() throws {
        let read = try XCTUnwrap(ESLogger.date(fromTime: "2026-10-04T00:01:54.394127173Z", legacy: true))
        XCTAssertEqual(read.timeIntervalSince1970, 1_791_072_114.394127173, accuracy: 1e-6)
    }
    
    /// Text that isn't a time has no date, legacy or not.
    func testDateFromTextThatIsNoTime() {
        XCTAssertNil(ESLogger.date(fromTime: "", legacy: false))
        XCTAssertNil(ESLogger.date(fromTime: "", legacy: true))
        XCTAssertNil(ESLogger.date(fromTime: "not a time, but 24 chars", legacy: true))
    }
}
