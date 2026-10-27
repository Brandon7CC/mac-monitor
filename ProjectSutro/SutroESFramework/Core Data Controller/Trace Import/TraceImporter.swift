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
/// Takes what `/usr/bin/eslogger` writes and what Mac Monitor writes or receives from its Security Extension, told
/// apart by their content rather than the file's extension:
/// - eslogger's JSON Lines, and its `--oslog` events read back with `log show` (`--style json` or `ndjson`, whose
///   entries carry the event as their `eventMessage`, or a text style, whose lines end with it);
/// - Mac Monitor's exports: JSONL (one compact event per line) and pretty JSON (pretty-printed events joined by "\n",
///   not an array). Since 3.0.0 an export is eslogger's JSON plus Mac Monitor's own fields, among them its telemetry
///   version (``TelemetrySchema/versionKey``), which is ignored: a re-export carries the version it's written in. 2.0
///   and 2.1 wrote their own shape;
/// - the Security Extension's own `Message` JSON (the XPC wire format), one per line;
/// - a JSON array of any of these, compact or pretty.
///
/// Every event is read with ``TraceDecoder``, which bridges these shapes for all event types at once instead of with a
/// decoder per type. eslogger's events lack what Mac Monitor adds to each event (its name, context, and the values Mac
/// Monitor derives from the event's own fields), so those are derived the way the Security Extension derives them
/// (``Message/enrich()``, ``ESEnrichable``), and so is the launched-by parent of each process an exec or fork creates,
/// from the trace alone (``TraceLaunchedByParents``).
///
/// The file is read incrementally (``TraceRecordReader``) and each batch goes through three stages at once. One batch
/// is decoded in parallel while the batch before is built into objects (``TraceInsertPipeline``) and the one before
/// that is saved. So memory stays flat whatever the file's size. Records that aren't events (malformed or truncated
/// JSON, other objects, events without a type or a time) are skipped and counted. Events of a type Mac Monitor doesn't
/// have are counted by name. A failed save (the disk is full) stops the import.
///
/// Start one with ``CoreDataController/openTrace(at:progress:completion:)``. Any Clear stops it.
public final class TraceImporter {
    /// The most events decoded and saved at a time.
    static let batchSize = 500
    /// Build each batch outside the store's queue while the one before saves (``TraceInsertPipeline``). Tests turn it
    /// off to compare with building and saving on the store's queue.
    static var pipelined = true
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
        /// One batch saving while the next is built and the one after is decoded, and what the saves did.
        let saving = DispatchSemaphore(value: 1)
        let saves = OSAllocatedUnfairLock(initialState: (events: 0, failed: false, range: ClosedRange<Date>?.none))
        let launchedByParents = TraceLaunchedByParents()
        /// Builds each batch here while the one before saves. It's made once the Clear that opened the trace has
        /// replaced the store, so no row gets an ID in the store that was replaced.
        store.privateMOC.performAndWait {}
        let pipeline = Self.pipelined ? TraceInsertPipeline(store: store, clear: clear) : nil
        
        /// A batch decoded and given its launched-by parents, waiting to be built and saved.
        var pending: [Message]?
        
        /// Decode the records read, in parallel, while the batch decoded before is built and handed to the store.
        ///
        /// - Returns: `false` once a save has failed.
        func flush() -> Bool {
            let batch = records
            records.removeAll(keepingCapacity: true)
            recordBytes = 0
            var decoded: [Result<Message, Error>] = []
            let decoding = DispatchGroup()
            if !batch.isEmpty {
                DispatchQueue.global(qos: .userInitiated).async(group: decoding) {
                    decoded = batch.concurrentMap { record in Result { try Self.message(from: record.json) } }
                }
            }
            let handedOK = pending.map(hand) ?? true
            pending = nil
            decoding.wait()
            guard handedOK else { return false }
            var messages: [Message] = []
            for (record, result) in zip(batch, decoded) {
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
            /// In file order, after the parallel decode: each event's launched-by parent is named from the events
            /// before it.
            launchedByParents.fill(&messages)
            pending = messages
            return true
        }
        
        /// Build a decoded batch while the batch before saves, wait for that save, and hand this one to the store.
        ///
        /// - Parameter messages: The batch, in file order.
        /// - Returns: `false` once a save has failed.
        func hand(_ messages: [Message]) -> Bool {
            let built = messages.isEmpty ? nil : pipeline?.build(messages)
            saving.wait()
            let failed = saves.withLock { $0.failed }
            let times = messages.map(\.message_darwin_time)
            guard !failed, let earliest = times.min(), let latest = times.max() else {
                if case .built(let batch)? = built { pipeline?.discard(batch) }
                saving.signal()
                return !failed
            }
            let span = earliest...latest
            let done = { [count = messages.count] (saved: Bool) in
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
            switch built {
            case nil: store.insertTraceEvents(messages, clear: clear, completion: done)
            case .built(let batch)?: store.saveTraceEvents(batch, clear: clear, completion: done)
            /// As ``CoreDataController/insertTraceEvents(_:clear:completion:)`` reports a batch of a closed trace.
            case .closed?: done(true)
            case .failed?: done(false)
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
        if flush(), let last = pending { _ = hand(last) }
        saving.wait()
        saving.signal()
        
        let (events, failed, range) = saves.withLock { ($0.events, $0.failed, $0.range) }
        (summary.saved, summary.timeRange) = (events, range)
        if failed { summary.error = Failure.storeFull }
        if let firstProblem {
            let line = firstProblem.line, reason = firstProblem.reason
            Self.logger.info("Skipped \(summary.skipped) records, first on line \(line): \(reason, privacy: .public)")
        }
        report(state())
        return summary
    }
    
    /// One event, from its JSON in any shape ``TraceImporter`` reads.
    ///
    /// Exports and eslogger don't carry `message_darwin_time`, the event's time as a `Date`: it's read back from `time`
    /// (``ESLogger/date(fromTime:legacy:)``), and `time` is kept in eslogger's format
    /// (``ESLogger/time(_:darwinTime:)``). A new path's directory, which exports from 2.0.0 to 2.1.0 leave out, is read
    /// back from the event's destination path, and a rename's `mode`, which 2.0.0 to 2.1.0 wrote as 0, is dropped (see
    /// ``Message/repairNewPath()``). An event without Mac Monitor's own fields (one of eslogger's) gets them derived
    /// from its Endpoint Security fields (``Message/enrich()``).
    ///
    /// - Parameter json: The event's JSON object, or a unified log entry whose `eventMessage` is one.
    /// - Returns: The event.
    /// - Throws: A `TraceImportError` or `DecodingError` if it isn't an event Mac Monitor can show.
    public static func message(from json: Data) throws -> Message {
        let object = try event(in: try JSONSerialization.jsonObject(with: json))
        /// Mac Monitor names every event it records or exports. eslogger doesn't.
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
        /// The Security Extension's own `Message` carries its time as seconds since 2001. One that isn't a time (more
        /// than about 3,000 years away) is read from `time` instead.
        let darwinTime = (object["message_darwin_time"] as? NSNumber)?.doubleValue
        if !(darwinTime.map { abs($0) < Self.maxDarwinTime } ?? false) {
            guard let date = ESLogger.date(fromTime: message.time, legacy: !enriching) else {
                throw TraceImportError.incomplete("no time")
            }
            message.message_darwin_time = date
        }
        message.time = ESLogger.time(message.time, darwinTime: message.message_darwin_time)
        message.deriveExecutableAge()
        message.repairNewPath()
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
        let trailer = object.count == 2 && object["finished"] != nil && object["count"] != nil
        throw trailer ? TraceImportError.logTrailer : TraceImportError.notAnEvent
    }
    
    /// Describe why a record was skipped, for the log.
    ///
    /// - Parameter error: The error decoding it.
    /// - Returns: A short reason, with the offending key path for a decoding error.
    static func describe(_ error: Error) -> String {
        guard let decoding = error as? DecodingError else {
            return (error as? LocalizedError)?.errorDescription ?? "not valid JSON"
        }
        guard let context = decoding.context else { return "\(decoding)" }
        return "\(context.codingPath.map(\.stringValue).joined(separator: ".")): \(context.debugDescription)"
    }
}
