//
//  TraceImporter+Summary.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Progress and results
extension TraceImporter {
    /// How far an import has got.
    public struct Progress: Equatable {
        /// Bytes of the file read so far.
        public let bytesRead: Int64
        /// The file's size when the import started.
        public let totalBytes: Int64
        /// Events handed to the store so far.
        public let events: Int
        /// `bytesRead` over `totalBytes`, from 0 to 1.
        public var fraction: Double { totalBytes > 0 ? min(1, Double(bytesRead) / Double(totalBytes)) : 1 }
    }
    
    /// How an import ended.
    public struct Summary {
        /// The trace.
        public let url: URL
        /// Events saved to the store.
        public internal(set) var saved = 0
        /// Records that weren't events: malformed or truncated JSON, JSON that isn't an Endpoint Security event, or an
        /// event without a type or a time.
        public internal(set) var skipped = 0
        /// The line the first skipped record starts on, counting from 1.
        public internal(set) var firstSkippedLine: Int?
        /// Events of types Mac Monitor doesn't have (eslogger logs every notify event), by eslogger's name for the type:
        /// the first ``maxUnsupportedTypes`` names, each cut to ``maxTypeNameLength`` characters.
        public internal(set) var unsupported: [String: Int] = [:]
        /// Events of types Mac Monitor doesn't have, past the first ``maxUnsupportedTypes`` names (the file names them).
        public internal(set) var unsupportedOther = 0
        /// How far through the file reading stopped, from 0 to 1, if ``TraceImporter/stop()`` (or a Clear) ended it early.
        public internal(set) var stoppedAt: Double?
        /// Why reading ended early: the file couldn't be read, or ``Failure/storeFull``.
        public internal(set) var error: Error?
        /// When the first and last saved events (in time) happened.
        public internal(set) var timeRange: ClosedRange<Date>?
        
        /// The most event type names ``unsupported`` keeps.
        public static let maxUnsupportedTypes = 64
        /// The longest event type name ``unsupported`` keeps.
        public static let maxTypeNameLength = 64
        
        /// Every event of a type Mac Monitor doesn't have, whatever its name.
        public var unsupportedCount: Int { unsupported.values.reduce(unsupportedOther, +) }
        
        /// Count a skipped record.
        ///
        /// - Parameter line: The line the record starts on. Records are decoded a batch at a time, so they aren't
        ///   necessarily counted in file order.
        mutating func skip(line: Int) {
            skipped += 1
            firstSkippedLine = min(firstSkippedLine ?? line, line)
        }
        
        /// Count an event of a type Mac Monitor doesn't have, under its name while fewer than ``maxUnsupportedTypes``
        /// names are kept, so a file can't grow the summary without bound.
        ///
        /// - Parameter name: eslogger's name for the event's type.
        mutating func countUnsupported(_ name: String) {
            let name = String(name.prefix(Self.maxTypeNameLength))
            if unsupported[name] != nil || unsupported.count < Self.maxUnsupportedTypes { unsupported[name, default: 0] += 1 }
            else { unsupportedOther += 1 }
        }
    }
    
    /// Why a file can't be opened, or why reading it ended early.
    public enum Failure: LocalizedError {
        /// The file holds nothing but whitespace.
        case empty
        /// No event Mac Monitor can show in the first ``TraceImporter/preflightRecords`` records (or
        /// ``TraceImporter/preflightBytes``) of the file.
        case notATrace
        /// The store couldn't save the events (the disk is full).
        case storeFull
        /// Not a file: a folder, a named pipe, or a device.
        case notAFile
        
        /// What went wrong, as a sentence for an alert.
        public var errorDescription: String? {
            switch self {
            case .empty: "The file is empty."
            case .notATrace: "No Endpoint Security events Mac Monitor can show were found at the start of the file."
            case .storeFull: "There isn't enough disk space to store the rest of the trace."
            case .notAFile: "Only files can be opened as traces."
            }
        }
    }
}


// MARK: - Errors
/// Why a record isn't imported.
enum TraceImportError: LocalizedError {
    /// JSON, but not an Endpoint Security event (it has no `event` or `process` object).
    case notAnEvent
    /// An event of a type Mac Monitor doesn't have, by eslogger's name for the type.
    case unsupportedEvent(String)
    /// The summary `log show --style ndjson` ends with: not an event, and not a problem.
    case logTrailer
    /// An event in name only: it has no event type, or no time.
    case incomplete(String)
    
    /// Why the record was skipped, for the log.
    var errorDescription: String? {
        switch self {
        case .notAnEvent: "not an Endpoint Security event"
        case .unsupportedEvent(let name): "Mac Monitor doesn't have \(name) events"
        case .logTrailer: "the end of a unified log listing"
        case .incomplete(let missing): "an event with \(missing)"
        }
    }
}
