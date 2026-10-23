//
//  StreamPipeline.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import CoreData


// MARK: - Output formats
/// What `macmonitor stream` writes.
public enum StreamOutputFormat: String, CaseIterable, Sendable {
    /// One line per event for people (``TextEventFormatter``): the default on a terminal.
    case text
    /// One export record per line (``ExportEncoder``), an eslogger superset: the default anywhere else.
    case jsonl
    /// Pretty-printed records, like Export telemetry ▸ JSON (pretty)
    case pretty
}


// MARK: - Pipeline
/// Turns each batch the Security Extension delivers into what `macmonitor` writes: decode, account for drops, leave
/// out the pipeline's own events and those the filter doesn't admit, format.
///
/// Every event is observed by the ``StreamDropMeter``, in order, before ``PipelineScope`` or the ``StreamFilter`` can
/// leave it out, so leaving one out never looks like a drop. Text output decodes only each event's header. JSONL, and
/// text with a filter that reads records, decode the whole `Message` once and take the header from it. Encoding a
/// record, at about 190 µs an event, is the slow part of a stream, so a batch of at least ``parallelThreshold`` events
/// is split across the formatter's encoders and encoded in parallel (measured on 21,768 real events: 5,100 events a
/// second with one encoder, 10,800 with four), then joined in order. With a limit (`--count`), the join stops at the
/// last event it allows, and later batches write nothing. Not thread-safe: one batch at a time.
public final class StreamPipeline {
    /// How events become output.
    public enum Formatter {
        /// Text lines, and encoders for each event's record when the filter reads records.
        case text(TextEventFormatter, records: [ExportEncoder] = [])
        /// Export records, one per line or pretty-printed, from one or more encoders.
        case jsonl([ExportEncoder])
        
        /// Export records from as many encoders as pay off on this Mac.
        ///
        /// - Parameters:
        ///   - model: The event model, such as ``ExportEncoder/model``.
        ///   - pretty: Pretty-print each record.
        /// - Returns: The formatter.
        public static func jsonl(model: NSManagedObjectModel, pretty: Bool = false) -> Formatter {
            .jsonl(encoders(model: model, pretty: pretty))
        }
        
        /// As many encoders as pay off on this Mac: half its active cores, from 1 to 4.
        ///
        /// - Parameters:
        ///   - model: The event model, such as ``ExportEncoder/model``.
        ///   - pretty: Pretty-print each record.
        /// - Returns: The encoders.
        public static func encoders(model: NSManagedObjectModel, pretty: Bool = false) -> [ExportEncoder] {
            let workers = min(4, max(1, ProcessInfo.processInfo.activeProcessorCount / 2))
            return (0..<workers).map { _ in ExportEncoder(model: model, pretty: pretty) }
        }
        
        /// The encoders that make records, if any.
        var encoders: [ExportEncoder] {
            switch self {
            case .text(_, let records): return records
            case .jsonl(let encoders): return encoders
            }
        }
    }
    
    /// The smallest batch worth splitting across encoders.
    static let parallelThreshold = 64
    /// The events lost, from their sequence numbers.
    public let meter = StreamDropMeter()
    /// Events written so far.
    public private(set) var written: Int = 0
    /// Events left out as the pipeline's own so far.
    public private(set) var suppressed: Int = 0
    /// Events the filter left out so far.
    public private(set) var filtered: Int = 0
    /// Events a `--where` predicate couldn't be evaluated on so far, which aren't written.
    public private(set) var unchecked: Int = 0
    /// Why the first of them couldn't be.
    public private(set) var uncheckedReason: String?
    /// Events that couldn't be read so far, which would be a bug in the Security Extension or here.
    public private(set) var unreadable: Int = 0
    /// The most events to write, if there's a limit.
    public let limit: Int?
    private let formatter: Formatter
    private let scope: PipelineScope
    /// The filter, one copy for each encoder.
    private let filters: [StreamFilter]
    /// Escape JSONL for a terminal (``TerminalSafeText/json(_:)``). Text is always escaped.
    private let escapesJSON: Bool
    
    /// - Parameters:
    ///   - formatter: How events become output. With a filter that reads records, it must have encoders.
    ///   - scope: Which events are the pipeline's own.
    ///   - forTerminal: Is the output a terminal? Then JSONL is escaped too.
    ///   - filter: Which events are written.
    ///   - limit: The most events to write, or `nil` for no limit.
    public init(formatter: Formatter, scope: PipelineScope, forTerminal: Bool, filter: StreamFilter = StreamFilter(),
                limit: Int? = nil) {
        precondition(!filter.readsRecords || !formatter.encoders.isEmpty, "A filter that reads records needs encoders.")
        self.formatter = formatter
        self.scope = scope
        self.escapesJSON = forTerminal
        self.filters = (0..<max(1, formatter.encoders.count)).map { _ in filter.copy }
        self.limit = limit
    }
    
    /// Has the pipeline written as many events as its limit allows?
    public var isFull: Bool {
        limit.map { written >= $0 } ?? false
    }
    
    /// Turn a batch into output.
    ///
    /// - Parameter batch: Wire events (`Message` JSON), oldest first.
    /// - Returns: The output for the events written, one line each, in order, up to the limit.
    public func process(_ batch: [Data]) -> Data {
        guard !isFull else { return Data() }
        let chunks: [Chunk]
        switch formatter {
        case .text(let text, let records) where records.isEmpty:
            chunks = [Chunk(batch[...], scope: scope, filter: filters[0]) { event, decoder in
                let header = try decoder.decode(EventHeader.self, from: event)
                return Decoded(header: header) { _ in Data(text.line(for: header).utf8) }
            }]
        case .text(let text, let encoders):
            chunks = encode(batch, with: encoders) { header, _ in Data(text.line(for: header).utf8) }
        case .jsonl(let encoders):
            let escapes = escapesJSON
            chunks = encode(batch, with: encoders) { _, record in escapes ? TerminalSafeText.json(record) : record }
        }
        return chunks.reduce(into: Data()) { output, chunk in
            chunk.headers.forEach(meter.observe)
            suppressed += chunk.suppressed
            filtered += chunk.filtered
            unchecked += chunk.unchecked
            uncheckedReason = uncheckedReason ?? chunk.uncheckedReason
            unreadable += chunk.unreadable
            let taken = min(chunk.ends.count, limit.map { $0 - written } ?? .max)
            written += taken
            /// The output up to the end of the last event taken, if any.
            output.append(chunk.output.prefix(taken == 0 ? 0 : chunk.ends[taken - 1]))
        }
    }
    
    /// Decode whole events and make their records, a large batch across the encoders in parallel.
    ///
    /// - Parameters:
    ///   - batch: Wire events.
    ///   - encoders: The encoders.
    ///   - format: Makes an event's output from its header and its record line.
    /// - Returns: The chunks, in order.
    private func encode(_ batch: [Data], with encoders: [ExportEncoder],
                        format: @escaping (EventHeader, Data) -> Data) -> [Chunk] {
        let parts = Self.split(batch, into: batch.count >= Self.parallelThreshold ? encoders.count : 1)
        var encoded = [Chunk?](repeating: nil, count: parts.count)
        let (scope, filters) = (scope, filters)
        encoded.withUnsafeMutableBufferPointer { encoded in
            DispatchQueue.concurrentPerform(iterations: parts.count) { index in
                encoded[index] = Chunk(parts[index], scope: scope, filter: filters[index]) { event, decoder in
                    let message = try decoder.decode(Message.self, from: event)
                    let header = EventHeader(message)
                    let record = { encoders[index].line(for: message) }
                    return Decoded(header: header, record: record) { made in format(header, made ?? record()) }
                }
            }
        }
        encoders.forEach { $0.reset() }
        return encoded.compactMap { $0 }
    }
    
    /// Split a batch into contiguous parts of nearly equal size.
    ///
    /// - Parameters:
    ///   - batch: The batch.
    ///   - count: How many parts, at least 1.
    /// - Returns: The parts, in order. None is empty unless the batch is.
    static func split(_ batch: [Data], into count: Int) -> [ArraySlice<Data>] {
        let size = max(1, (batch.count + count - 1) / max(1, count))
        guard batch.count > size else { return [batch[...]] }
        return stride(from: 0, to: batch.count, by: size).map { batch[$0..<min($0 + size, batch.count)] }
    }
}


// MARK: - Chunks
extension StreamPipeline {
    /// An event read from the wire, with what can be made from it only once it's needed.
    struct Decoded {
        /// The event's header.
        let header: EventHeader
        /// Makes the event's export record line, if the format can: only for a filter that reads records.
        var record: (() -> Data)?
        /// Makes the event's output, given the record line if the filter made it.
        let output: (Data?) -> Data
    }
    
    /// What one formatter made of a run of a batch's events: every event's header, in order, for the meter, and the
    /// output for those written. Made on any thread.
    struct Chunk {
        /// Every event read, in order, written or not.
        private(set) var headers: [EventHeader] = []
        /// The output for the events written.
        private(set) var output = Data()
        /// Where each written event's output ends in ``output``.
        private(set) var ends: [Int] = []
        /// Events left out as the pipeline's own.
        private(set) var suppressed: Int = 0
        /// Events the filter left out.
        private(set) var filtered: Int = 0
        /// Events a `--where` predicate couldn't be evaluated on.
        private(set) var unchecked: Int = 0
        /// Why the first of them couldn't be.
        private(set) var uncheckedReason: String?
        /// Events that couldn't be read.
        private(set) var unreadable: Int = 0
        
        /// Read, filter and format a run of events.
        ///
        /// - Parameters:
        ///   - events: Wire events.
        ///   - scope: Which events are the pipeline's own.
        ///   - filter: Which events are written.
        ///   - decode: Decodes an event.
        init(_ events: ArraySlice<Data>, scope: PipelineScope, filter: StreamFilter,
             decode: (Data, JSONDecoder) throws -> Decoded) {
            let decoder = JSONDecoder()
            for event in events {
                guard let decoded = try? decode(event, decoder) else {
                    unreadable += 1
                    continue
                }
                headers.append(decoded.header)
                guard !scope.suppresses(decoded.header) else {
                    suppressed += 1
                    continue
                }
                guard filter.admits(decoded.header) else {
                    filtered += 1
                    continue
                }
                /// Made only once the header passes: it's the slow part.
                let record = filter.readsRecords ? decoded.record?() : nil
                guard admits(record, to: filter) else { continue }
                output.append(decoded.output(record))
                ends.append(output.count)
            }
        }
        
        /// Does the filter admit an event's record? Count the event if not.
        ///
        /// - Parameters:
        ///   - record: The event's record line, or `nil` when the filter doesn't read records.
        ///   - filter: The filter.
        /// - Returns: `true` if the event is written.
        private mutating func admits(_ record: Data?, to filter: StreamFilter) -> Bool {
            guard let record else { return true }
            do {
                let object = (try? JSONSerialization.jsonObject(with: record)) as? NSDictionary ?? NSDictionary()
                if try filter.admits(record: object) { return true }
                filtered += 1
            } catch {
                unchecked += 1
                uncheckedReason = uncheckedReason ?? "\(error)"
            }
            return false
        }
    }
}
