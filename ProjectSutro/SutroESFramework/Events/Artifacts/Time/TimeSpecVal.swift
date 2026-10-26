//
//  TimeSpecVal.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/16/25.
//

import Foundation

/// ISO 8601 in UTC (`yyyy-MM-dd'T'HH:mm:ssZ`). A value type, so one shared instance is safe on any thread.
///
/// Replaces a new `ISO8601DateFormatter` (`.withInternetDateTime`) per call, ~70 µs each on the Core Data insert path
/// (#84). Output is identical for whole-second dates, which is all ``TimeSpec`` and ``TimeVal`` format: the formatter
/// rounds a fractional second while this truncates, and the fraction is appended separately below.
private let iso8601Format = Date.ISO8601FormatStyle()

/// A UTC time with a fraction of a second, as ``TimeSpec/humanFormat()`` and ``TimeVal/humanFormat()`` write it.
///
/// - Parameters:
///   - seconds: Seconds since 1970.
///   - fraction: The fraction of a second, in units of 10^-`digits` seconds.
///   - digits: The fraction's width: 9 for a `timespec`, 6 for a `timeval`.
/// - Returns: The time, from ``ESLogger/utcTime(seconds:fraction:digits:)`` or else ``iso8601Format``.
private func humanTime(seconds: Int, fraction: Int, digits: Int) -> String {
    if let time = ESLogger.utcTime(seconds: seconds, fraction: fraction, digits: digits) { return time }
    let base = Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(iso8601Format)
    return base.replacingOccurrences(of: "Z", with: ".\(String(format: "%0\(digits)d", fraction))Z")
}


/// Description: represents a simple calendar time, or an elapsed time, with sub-second resolution.
/// https://www.gnu.org/software/libc/manual/html_node/Time-Types.html
// Ensure TimeSpec conforms to Codable and Equatable
public struct TimeSpec: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    public var tv_sec, tv_nsec: Int
    
    public init(from spec: Darwin.timespec) {
        self.tv_sec = spec.tv_sec
        self.tv_nsec = spec.tv_nsec
    }
    
    /// Returns the time as an ISO 8601 formatted string with nanosecond precision.
    public func humanFormat() -> String {
        humanTime(seconds: tv_sec, fraction: tv_nsec, digits: 9)
    }
}

/// An older type for representing a simple calendar time, or an elapsed time, with sub-second resolution. It is almost the same as struct timespec, but provides only microsecond resolution.
/// https://www.gnu.org/software/libc/manual/html_node/Time-Types.html
// Ensure TimeVal conforms to Codable and Equatable
public struct TimeVal: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    public var tv_sec, tv_usec: Int
    
    public init(from val: Darwin.timeval) {
        self.tv_sec = val.tv_sec
        self.tv_usec = Int(val.tv_usec)
    }
    
    /// Returns the time as an ISO 8601 formatted string with microsecond precision.
    public func humanFormat() -> String {
        humanTime(seconds: tv_sec, fraction: tv_usec, digits: 6)
    }
}
