//
//  ESExtensions.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 2/15/25.
//

import Foundation


extension es_string_token_t {
    /// The token's text as `eslogger(1)` writes it: `nil` only when `data` is `NULL`, otherwise its `length` bytes
    /// decoded as UTF-8 (invalid bytes become U+FFFD), so an empty token is "".
    ///
    /// Endpoint Security sets `data` to `NULL` for an optional string that's absent, which eslogger writes as `null`.
    /// For a string the SDK doesn't call optional, read it as `string ?? ""`: the "" only keeps a `NULL` it never sends
    /// from stopping the Security Extension. `length` bounds the read, so a token needn't end in a NUL.
    var string: String? {
        guard let data else { return nil }
        return String(decoding: UnsafeRawBufferPointer(start: data, count: length), as: UTF8.self)
    }
}

public extension Optional where Wrapped == String {
    /// The string, or `nil` when it's `nil` or empty.
    ///
    /// For showing a value Endpoint Security can leave out either way, such as a process's signing ID: `NULL` is kept
    /// as `nil` and an empty token as "", as eslogger writes them, but both mean there's none to show.
    var nonEmpty: String? {
        flatMap { $0.isEmpty ? nil : $0 }
    }
}

/// A SHA-256 digest in hex, uppercase as `eslogger(1)` writes it.
func sha256HexString(_ digest: es_sha256_t) -> String {
    ESLogger.hex(digest)
}

/// A code directory hash in hex, uppercase as `eslogger(1)` writes it.
func cdhashToString(cdhash: es_cdhash_t) -> String {
    ESLogger.hex(cdhash)
}


// MARK: - eslogger format
/// The rules Mac Monitor's exports and CLI follow so that every field `eslogger(1)` writes has eslogger's key path and value.
///
/// Mac Monitor's JSON is eslogger's JSON plus Mac Monitor's own fields. `eslogger` has no published schema; these rules were
/// verified against its output on macOS 27.0 (26A5353q):
/// * `time` is UTC with nine fractional digits (``time(_:)``).
/// * Hashes are uppercase hex (``hex(_:)``).
/// * A field eslogger writes is always written: `null` when the value is absent (encode the optional with `encode`, never
///   `encodeIfPresent`). Mac Monitor's own fields may be left out.
/// * `seq_num` and `global_seq_num` count the messages one Endpoint Security client received, so they're Mac Monitor's own
///   and never equal eslogger's.
/// * `remote_thread_create`'s `thread_state.state` is always `null`: eslogger writes no thread state bytes. Mac Monitor
///   keeps them in its own `state_base64` (``ThreadState``).
enum ESLogger {
    /// The `schema_version` of the eslogger output these rules match.
    static let schemaVersion = 1
    
    /// The shape of an eslogger `time`, for example `2026-10-04T00:01:54.394127173Z`: `0` stands for any digit.
    private static let timeTemplate = Array("0000-00-00T00:00:00.000000000Z".utf8)
    /// The seconds from 1970 to 2001 (a `Date`'s reference date), in microseconds.
    private static let referenceDateMicroseconds: Int64 = 978_307_200 * 1_000_000
    
    /// `bytes` in uppercase hex.
    ///
    /// - Parameter bytes: A fixed-size value such as `es_cdhash_t` or `es_sha256_t`.
    /// - Returns: Two hex digits per byte.
    static func hex<T>(_ bytes: T) -> String {
        withUnsafeBytes(of: bytes) { $0.map { String(format: "%02X", $0) }.joined() }
    }
    
    /// A message's `time` as eslogger writes it.
    ///
    /// - Parameter time: `es_message_t.time`.
    /// - Returns: The time in UTC with nine fractional digits.
    static func time(_ time: timespec) -> String {
        TimeSpec(from: time).humanFormat()
    }
    
    /// Is `time` exactly as eslogger writes it: UTC to the nanosecond, `2026-10-04T00:01:54.394127173Z`?
    ///
    /// - Parameter time: A message's `time`.
    /// - Returns: `true` for eslogger's format, which Mac Monitor also writes since 2.2.0.
    static func isESLoggerTime(_ time: String) -> Bool {
        matches(time, timeTemplate)
    }
    
    /// Does `text` have a template's shape?
    ///
    /// - Parameters:
    ///   - text: The text.
    ///   - template: The shape, in UTF-8: `0` stands for any digit, and any other byte for itself.
    /// - Returns: `true` if `text` is as long as `template` and matches it byte for byte.
    private static func matches(_ text: String, _ template: [UInt8]) -> Bool {
        let digits = UInt8(ascii: "0")...UInt8(ascii: "9")
        var text = text
        return text.withUTF8 { utf8 in
            utf8.count == template.count && zip(utf8, template).allSatisfy { byte, expected in
                expected == UInt8(ascii: "0") ? digits.contains(byte) : byte == expected
            }
        }
    }
    
    /// `time` from a message, rebuilt when it came from a Security Extension older than 2.2.0.
    ///
    /// Those sent local time to the millisecond with a literal `Z`, which can't be read back exactly. The rebuilt value
    /// comes from `message_darwin_time`, to the microsecond: older Security Extensions and 2.1 exports carry no finer
    /// time, and rounding drops the error of the `Double` that holds it (at most about 0.12 microseconds) rather than
    /// printing it as nanoseconds.
    ///
    /// - Parameters:
    ///   - time: The message's `time`.
    ///   - darwinTime: The message's `message_darwin_time`.
    /// - Returns: `time` if it's already in eslogger's format (``isESLoggerTime(_:)``), otherwise `darwinTime` in it;
    ///   `time` as it is if `darwinTime` is too far from 1970 to be a time.
    static func time(_ time: String, darwinTime: Date) -> String {
        guard !isESLoggerTime(time) else { return time }
        guard let since2001 = Int64(exactly: (darwinTime.timeIntervalSinceReferenceDate * 1_000_000).rounded()) else {
            return time
        }
        let (since1970, overflow) = since2001.addingReportingOverflow(referenceDateMicroseconds)
        guard !overflow else { return time }
        /// Floored, so a time before 1970 counts its fraction up from the second before.
        let (seconds, microseconds) = since1970.quotientAndRemainder(dividingBy: 1_000_000)
        let floored = microseconds < 0 ? (seconds - 1, microseconds + 1_000_000) : (seconds, microseconds)
        return Self.time(timespec(tv_sec: Int(floored.0), tv_nsec: Int(floored.1) * 1_000))
    }
    
    // MARK: Reading times back
    /// The shape of a `time` written by Mac Monitor up to 2.1.0, for example `2026-10-03T17:01:59.285Z`: `0` stands
    /// for any digit.
    private static let legacyTimeTemplate = Array("0000-00-00T00:00:00.000Z".utf8)
    
    /// When an event happened, from its `time` as eslogger or any version of Mac Monitor wrote it.
    ///
    /// eslogger's `time` (and Mac Monitor's since 2.2.0) is UTC to the nanosecond, and is read exactly. Up to 2.1.0 Mac
    /// Monitor wrote the recording Mac's local time to the millisecond with a literal `Z`; that's read in this Mac's time
    /// zone with the formatter that wrote it, so it's exact to the millisecond when both Macs share a time zone.
    ///
    /// - Parameters:
    ///   - time: An event's `time`.
    ///   - legacy: Could the event come from Mac Monitor 2.1.0 or older (it's Mac Monitor's, not eslogger's)? Only then
    ///     is a `time` of that shape local time; anywhere else it's UTC.
    /// - Returns: The time, or `nil` if `time` isn't one.
    static func date(fromTime time: String, legacy: Bool) -> Date? {
        if legacy, matches(time, legacyTimeTemplate) { return legacyFormatter.date(from: time) }
        return utcTimespec(from: time).map { ProcessHelpers.timespecToTimestamp(timespec: $0) }
    }
    
    /// A UTC time as eslogger writes `time`, or as ``TimeSpec/humanFormat()`` and ``TimeVal/humanFormat()`` write
    /// theirs: `2026-10-04T00:01:54.394127173Z`, with up to nine fractional digits (or none).
    ///
    /// Plain arithmetic rather than `timegm`, which takes a process-wide time zone lock on every call.
    ///
    /// - Parameter text: The string to read.
    /// - Returns: The time since 1970, or `nil` if `text` isn't one.
    static func utcTimespec(from text: String) -> timespec? {
        var text = text
        return text.withUTF8 { utf8 -> timespec? in
            guard (20...30).contains(utf8.count), utf8.count != 21, utf8[utf8.count - 1] == UInt8(ascii: "Z"),
                  utf8[10] == UInt8(ascii: "T"), utf8.count == 20 || utf8[19] == UInt8(ascii: ".") else { return nil }
            func number(_ range: Range<Int>) -> Int? {
                var result = 0
                for byte in utf8[range] {
                    guard (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte) else { return nil }
                    result = result * 10 + Int(byte - UInt8(ascii: "0"))
                }
                return result
            }
            guard let year = number(0..<4), let month = number(5..<7), let day = number(8..<10), let hour = number(11..<13),
                  let minute = number(14..<16), let second = number(17..<19), (1...12).contains(month),
                  let fraction = utf8.count == 20 ? 0 : number(20..<utf8.count - 1) else { return nil }
            /// Days since 1970-01-01 in the proleptic Gregorian calendar (Howard Hinnant's `days_from_civil`).
            let y = month <= 2 ? year - 1 : year, era = y / 400, yearOfEra = y - era * 400
            let dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1
            let days = era * 146_097 + yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear - 719_468
            var nanoseconds = fraction
            for _ in 0..<max(0, 9 - (utf8.count - 21)) { nanoseconds *= 10 }
            return timespec(tv_sec: days * 86_400 + hour * 3_600 + minute * 60 + second, tv_nsec: nanoseconds)
        }
    }
    
    /// ``ProcessHelpers/timestampFormatter``, which wrote `time` up to 2.1.0, one per thread: a `DateFormatter`
    /// serializes its callers, which held parallel decoding to the speed of one thread.
    private static var legacyFormatter: DateFormatter {
        let key = "com.swiftlydetecting.agent.ESLogger.legacyFormatter"
        if let formatter = Foundation.Thread.current.threadDictionary[key] as? DateFormatter { return formatter }
        let formatter = ProcessHelpers.timestampFormatter.copy() as! DateFormatter
        Foundation.Thread.current.threadDictionary[key] = formatter
        return formatter
    }
}
