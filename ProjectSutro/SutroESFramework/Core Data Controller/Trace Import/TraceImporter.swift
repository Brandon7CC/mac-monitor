//
//  TraceImporter.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import OSLog
import os


// MARK: - Trace importer
/// Reads a trace file into the event store for File > Open Trace… (#38), like opening a saved Process Monitor log.
///
/// Takes what `/usr/bin/eslogger` writes and what Mac Monitor writes or receives from its Security Extension, told apart by
/// their content rather than the file's extension:
/// - eslogger's JSON Lines, and its `--oslog` events read back with `log show` (`--style json` or `ndjson`, whose
///   entries carry the event as their `eventMessage`, or a text style, whose lines end with it);
/// - Mac Monitor's exports: JSONL (one compact event per line) and pretty JSON (pretty-printed events joined by "\n", not
///   an array). Since 2.2.0 an export is eslogger's JSON plus Mac Monitor's own fields; 2.0 and 2.1 wrote their own shape;
/// - the Security Extension's own `Message` JSON (the XPC wire format), one per line;
/// - a JSON array of any of these, compact or pretty.
///
/// Every event is read with ``TraceDecoder``, which bridges these shapes for all event types at once instead of with a
/// decoder per type. eslogger's events lack what Mac Monitor adds to each event (its name, context, and the values Mac
/// Monitor derives from the event's own fields), so those are derived the way the Security Extension derives them
/// (``Message/enrich()``, ``ESEnrichable``).
///
/// The file is read incrementally (``TraceRecordReader``), decoded in parallel a batch at a time, and each batch is saved
/// while the next is decoded, so memory stays flat whatever the file's size. Records that aren't events (malformed or
/// truncated JSON, other objects, events without a type or a time) are skipped and counted, and events of a type Mac
/// Monitor doesn't have are counted by name. A failed save (the disk is full) stops the import.
///
/// Start one with ``CoreDataController/openTrace(at:progress:completion:)``. Any Clear stops it.
public final class TraceImporter {
    /// The most events decoded and saved at a time.
    static let batchSize = 500
    /// The most bytes of records decoded at a time: a batch of large records is flushed before it has ``batchSize``.
    static let batchBytes = 64 << 20
    /// How much of a file ``preflight(_:)`` reads looking for an event.
    public static let preflightBytes = 4 << 20
    /// How many records ``preflight(_:)`` decodes looking for an event, so a file of records that aren't events can't
    /// hold up opening it.
    public static let preflightRecords = 1_000
    /// The furthest a `message_darwin_time` (seconds since 2001) can be from 2001 and still be read as a time.
    static let maxDarwinTime: Double = 1e11
    /// The shortest time between progress reports: a tenth of a second.
    private static let reportInterval: UInt64 = 100_000_000
    /// Notes why records were skipped.
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "TraceImporter")
    
    /// The trace being read.
    public let url: URL
    /// The event store the trace is read into.
    private unowned let store: CoreDataController
    /// The Clear that opened this trace: its inserts carry it.
    private let clear: Int
    /// Where the file is read and decoded.
    private let queue = DispatchQueue(label: "com.swiftlydetecting.agent.TraceImporter", qos: .userInitiated)
    /// Has ``stop()`` been called? Set from any thread, read on `queue`.
    private let stopped = OSAllocatedUnfairLock(initialState: false)
    /// Has ``stop()`` been called? Read on `queue`.
    private var isStopped: Bool { stopped.withLock { $0 } }
    
    /// - Parameters:
    ///   - url: The trace.
    ///   - store: The event store to read it into.
    ///   - clear: The Clear that opened the trace (``CoreDataController/clearSystemEvents(source:)``).
    init(url: URL, store: CoreDataController, clear: Int) {
        self.url = url
        self.store = store
        self.clear = clear
    }
    
    /// Stop reading after the record being read, keeping the events read so far. Any thread.
    public func stop() { stopped.withLock { $0 = true } }
    
    // MARK: Preflight
    
    /// Check that `url` is a trace before anything is cleared: it opens, and its first ``preflightRecords`` records (in
    /// its first ``preflightBytes``) hold an event Mac Monitor can show.
    ///
    /// Reads and decodes on the calling thread: call it off the main thread.
    ///
    /// - Parameter url: The file the user chose.
    /// - Throws: The error opening the file, ``Failure/notAFile``, ``Failure/empty``, or ``Failure/notATrace``.
    public static func preflight(_ url: URL) throws {
        let reader = try TraceRecordReader(url: url, limit: Int64(preflightBytes))
        var records = 0
        while records < preflightRecords, let record = try reader.next() {
            records += 1
            if case .object(let json, _) = record, (try? message(from: json)) != nil { return }
        }
        throw records == 0 ? Failure.empty : Failure.notATrace
    }
    
    // MARK: Import
    
    /// Read the file into the store, asynchronously on the importer's queue.
    ///
    /// - Parameters:
    ///   - progress: Called on the main thread, at most ten times a second, and once more when reading ends.
    ///   - completion: Called on the main thread once, after the last batch is saved.
    func run(progress: @escaping (Progress) -> Void, completion: @escaping (Summary) -> Void) {
        queue.async {
            let summary = self.read { state in DispatchQueue.main.async { progress(state) } }
            DispatchQueue.main.async { completion(summary) }
        }
    }
    
    /// Read, decode, and save every event in the file. Runs on `queue`.
    ///
    /// - Parameter report: Receives the progress, at most ten times a second and once at the end.
    /// - Returns: What was read.
    private func read(report: (Progress) -> Void) -> Summary {
        var summary = Summary(url: url), records: [(line: Int, json: Data)] = [], recordBytes = 0, handed = 0
        var firstProblem: (line: Int, reason: String)?
        /// One batch saving while the next is read and decoded, and what the saves did.
        let saving = DispatchSemaphore(value: 1)
        let saves = OSAllocatedUnfairLock(initialState: (events: 0, failed: false, range: ClosedRange<Date>?.none))
        
        /// Decode the records read, wait for the batch being saved, and hand these to the store.
        ///
        /// - Returns: `false` once a save has failed.
        func flush() -> Bool {
            var messages: [Message] = []
            for (record, result) in zip(records, Self.decode(records.map(\.json))) {
                switch result {
                case .success(let message):
                    messages.append(message)
                case .failure(TraceImportError.unsupportedEvent(let name)):
                    summary.countUnsupported(name)
                case .failure(TraceImportError.logTrailer):
                    break
                case .failure(let error):
                    summary.skip(line: record.line)
                    if record.line < firstProblem?.line ?? .max { firstProblem = (record.line, Self.describe(error)) }
                }
            }
            records.removeAll(keepingCapacity: true)
            recordBytes = 0
            saving.wait()
            let failed = saves.withLock { $0.failed }
            let times = messages.map(\.message_darwin_time)
            guard !failed, let earliest = times.min(), let latest = times.max() else {
                saving.signal()
                return !failed
            }
            let span = earliest...latest
            store.insertTraceEvents(messages, clear: clear) { [count = messages.count] saved in
                saves.withLock { state in
                    guard saved else {
                        state.failed = true
                        return
                    }
                    state.events += count
                    state.range = state.range?.including(span) ?? span
                }
                saving.signal()
            }
            handed += messages.count
            return true
        }
        
        var reader: TraceRecordReader?, reported: UInt64 = 0
        /// How far reading has got.
        func state() -> Progress {
            Progress(bytesRead: reader?.bytesRead ?? 0, totalBytes: reader?.totalBytes ?? 0, events: handed)
        }
        do {
            let file = try TraceRecordReader(url: url)
            reader = file
            reading: while let record = try file.next() {
                switch record {
                case .object(let json, let line):
                    records.append((line, json))
                    recordBytes += json.count
                    if records.count == Self.batchSize || recordBytes >= Self.batchBytes, !flush() { break reading }
                case .malformed(let line):
                    summary.skip(line: line)
                    if line < firstProblem?.line ?? .max { firstProblem = (line, "incomplete or malformed JSON") }
                }
                if isStopped {
                    summary.stoppedAt = state().fraction
                    break
                }
                let now = DispatchTime.now().uptimeNanoseconds
                if now - reported >= Self.reportInterval {
                    reported = now
                    report(state())
                }
            }
        } catch {
            summary.error = error
        }
        /// The events read so far, unless a save has failed.
        _ = flush()
        saving.wait()
        saving.signal()
        
        let (events, failed, range) = saves.withLock { ($0.events, $0.failed, $0.range) }
        (summary.saved, summary.timeRange) = (events, range)
        if failed { summary.error = Failure.storeFull }
        if let firstProblem {
            Self.logger.info("Skipped \(summary.skipped) records, first on line \(firstProblem.line): \(firstProblem.reason, privacy: .public)")
        }
        report(state())
        return summary
    }
    
    /// Decode a batch of records, in parallel, keeping their order.
    ///
    /// - Parameter records: Each record's JSON.
    /// - Returns: Each record's event, or why it isn't one.
    private static func decode(_ records: [Data]) -> [Result<Message, Error>] {
        var results = [Result<Message, Error>](repeating: .failure(CancellationError()), count: records.count)
        results.withUnsafeMutableBufferPointer { buffer in
            let slots = buffer
            DispatchQueue.concurrentPerform(iterations: records.count) { index in
                /// The calling thread decodes some records too, inside the import's one long work item: drain as we go.
                slots[index] = autoreleasepool { Result { try message(from: records[index]) } }
            }
        }
        return results
    }
    
    /// One event, from its JSON in any shape ``TraceImporter`` reads.
    ///
    /// Exports and eslogger don't carry `message_darwin_time`, the event's time as a `Date`: it's read back from `time`
    /// (``ESLogger/date(fromTime:legacy:)``), and `time` is kept in eslogger's format (``ESLogger/time(_:darwinTime:)``).
    /// A new path's directory, which exports from 2.0.0 to 2.1.0 leave out, is read back from the event's destination
    /// path (see ``Message/restoreNewPathDirectory()``). An event without Mac Monitor's own fields (one of eslogger's)
    /// gets them derived from its Endpoint Security fields (``Message/enrich()``).
    ///
    /// - Parameter json: The event's JSON object, or a unified log entry whose `eventMessage` is one.
    /// - Returns: The event.
    /// - Throws: A `TraceImportError` or `DecodingError` if it isn't an event Mac Monitor can show.
    public static func message(from json: Data) throws -> Message {
        let object = try event(in: try JSONSerialization.jsonObject(with: json))
        /// Mac Monitor names every event it records or exports; eslogger doesn't.
        let enriching = object["es_event_type"] == nil
        var message: Message
        do {
            message = try TraceDecoder(object, enriching: enriching).decode(Message.self)
        } catch let error as DecodingError where error.context?.codingPath.map(\.stringValue) == ["event"] {
            /// `event` names no case of ``EventType``.
            throw TraceImportError.unsupportedEvent((object["event"] as? NSDictionary)?.allKeys.first as? String ?? "?")
        }
        /// Every key is optional to the decoder: a record that's an event in name only isn't shown.
        if case .unknown = message.event { throw TraceImportError.incomplete("no event type") }
        /// The Security Extension's own `Message` carries its time as seconds since 2001; one that isn't a time (more
        /// than about 3,000 years away) is read from `time` instead.
        let darwinTime = (object["message_darwin_time"] as? NSNumber)?.doubleValue
        if !(darwinTime.map { abs($0) < Self.maxDarwinTime } ?? false) {
            guard let date = ESLogger.date(fromTime: message.time, legacy: !enriching) else { throw TraceImportError.incomplete("no time") }
            message.message_darwin_time = date
        }
        message.time = ESLogger.time(message.time, darwinTime: message.message_darwin_time)
        message.restoreNewPathDirectory()
        return message
    }
    
    /// The event a record holds: the record itself, or, for a unified log entry (eslogger `--oslog`, read back with
    /// `log show --style json` or `ndjson`), the JSON of its message.
    ///
    /// - Parameter record: The record's JSON value.
    /// - Returns: The event's JSON object.
    /// - Throws: `TraceImportError.notAnEvent`, `TraceImportError.logTrailer` for the summary that ends
    ///   `log show --style ndjson`, or the error parsing a log entry's message (cut at the unified log's 32 KB).
    static func event(in record: Any) throws -> NSDictionary {
        guard let object = record as? NSDictionary else { throw TraceImportError.notAnEvent }
        if object["event"] is NSDictionary, object["process"] is NSDictionary { return object }
        if let text = object["eventMessage"] as? String, let start = text.firstIndex(of: "{") {
            return try event(in: try JSONSerialization.jsonObject(with: Data(text[start...].utf8)))
        }
        throw object.count == 2 && object["finished"] != nil && object["count"] != nil ? TraceImportError.logTrailer : TraceImportError.notAnEvent
    }
    
    /// Describe why a record was skipped, for the log.
    ///
    /// - Parameter error: The error decoding it.
    /// - Returns: A short reason, with the offending key path for a decoding error.
    static func describe(_ error: Error) -> String {
        guard let decoding = error as? DecodingError else { return (error as? LocalizedError)?.errorDescription ?? "not valid JSON" }
        guard let context = decoding.context else { return "\(decoding)" }
        return "\(context.codingPath.map(\.stringValue).joined(separator: ".")): \(context.debugDescription)"
    }
}
