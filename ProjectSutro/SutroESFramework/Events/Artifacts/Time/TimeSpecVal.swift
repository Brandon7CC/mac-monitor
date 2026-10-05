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
        if let time = ESLogger.utcTime(seconds: tv_sec, fraction: tv_nsec, digits: 9) { return time }
        let date = Date(timeIntervalSince1970: TimeInterval(tv_sec))
        let nanoseconds = String(format: "%09d", tv_nsec)
        
        let baseString = date.formatted(iso8601Format)
        return baseString.replacingOccurrences(of: "Z", with: ".\(nanoseconds)Z")
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
        if let time = ESLogger.utcTime(seconds: tv_sec, fraction: tv_usec, digits: 6) { return time }
        let date = Date(timeIntervalSince1970: TimeInterval(tv_sec))
        let microseconds = String(format: "%06d", tv_usec) // Ensures 6-digit microsecond precision
        
        let baseString = date.formatted(iso8601Format)
        return baseString.replacingOccurrences(of: "Z", with: ".\(microseconds)Z")
    }
}
