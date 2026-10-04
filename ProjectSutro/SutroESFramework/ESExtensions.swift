//
//  ESExtensions.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 2/15/25.
//

import Foundation


extension es_string_token_t {
    func toString() -> String? {
        guard length > 0 else { return nil }
        return String(cString: data)
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
enum ESLogger {
    /// The `schema_version` of the eslogger output these rules match.
    static let schemaVersion = 1
    
    /// The length of an eslogger `time`, for example `2026-10-04T00:01:54.394127173Z`.
    private static let timeLength = 30
    
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
    
    /// `time` from a message, rebuilt when it came from a Security Extension older than 2.2.0.
    ///
    /// Those sent local time to the millisecond with a literal `Z`, which can't be read back exactly. The rebuilt value comes
    /// from `message_darwin_time` and is within a few hundred nanoseconds of the real one.
    ///
    /// - Parameters:
    ///   - time: The message's `time`.
    ///   - darwinTime: The message's `message_darwin_time`.
    /// - Returns: `time` in eslogger's format.
    static func time(_ time: String, darwinTime: Date) -> String {
        guard time.utf8.count != timeLength else { return time }
        let since1970 = darwinTime.timeIntervalSince1970
        var seconds = Int(since1970.rounded(.down)), nanoseconds = Int(((since1970 - Double(seconds)) * 1e9).rounded())
        if nanoseconds >= 1_000_000_000 { seconds += 1; nanoseconds -= 1_000_000_000 }
        return Self.time(timespec(tv_sec: seconds, tv_nsec: nanoseconds))
    }
}
