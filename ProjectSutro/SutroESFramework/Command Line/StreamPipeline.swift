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
    /// The same records pretty-printed, like Export telemetry ▸ JSON (pretty). Easier to read in a terminal.
    case pretty
}


// MARK: - Pipeline
/// Turns each batch the Security Extension delivers into what `macmonitor` writes: decode, account for drops, leave
/// out the pipeline's own events, format.
///
/// Every event is observed by the ``StreamDropMeter``, in order, before ``PipelineScope`` can suppress it, so
/// suppression never looks like a drop. Text output decodes only each event's header. JSONL decodes the whole
/// `Message` once and takes the header from it; at about 190 µs an event it's the slow part of a stream, so a batch of
/// at least ``parallelThreshold`` events is split across the formatter's encoders and encoded in parallel (measured
/// on 21,768 real events: 5,100 events a second with one encoder, 10,800 with four), then joined in order. Not
/// thread-safe: one batch at a time.
public final class StreamPipeline {
    /// How events become output.
    public enum Formatter {
        /// Text lines.
        case text(TextEventFormatter)
        /// Export records, one per line or pretty-printed, from one or more encoders.
        case jsonl([ExportEncoder])
        
        /// Export records from as many encoders as pay off on this Mac: half its active cores, from 1 to 4.
        ///
        /// - Parameters:
        ///   - model: The event model, such as ``ExportEncoder/model``.
        ///   - pretty: Pretty-print each record (``StreamOutputFormat/pretty``) instead of writing one per line.
        /// - Returns: The formatter.
        public static func jsonl(model: NSManagedObjectModel, pretty: Bool = false) -> Formatter {
            let workers = min(4, max(1, ProcessInfo.processInfo.activeProcessorCount / 2))
            return .jsonl((0..<workers).map { _ in ExportEncoder(model: model, pretty: pretty) })
        }
    }
    
    /// The smallest JSONL batch worth splitting across encoders.
    static let parallelThreshold = 64
    /// The events lost, from their sequence numbers.
    public let meter = StreamDropMeter()
    /// Events written so far.
    public private(set) var written: Int = 0
    /// Events left out as the pipeline's own so far.
    public private(set) var suppressed: Int = 0
    /// Events that couldn't be read so far, which would be a bug in the Security Extension or here.
    public private(set) var unreadable: Int = 0
    private let formatter: Formatter
    private let scope: PipelineScope
    /// Escape JSONL for a terminal (``TerminalSafeText/json(_:)``). Text is always escaped.
    private let escapesJSON: Bool
    
    /// - Parameters:
    ///   - formatter: How events become output.
    ///   - scope: Which events are the pipeline's own.
    ///   - forTerminal: Is the output a terminal? Then JSONL is escaped too.
    public init(formatter: Formatter, scope: PipelineScope, forTerminal: Bool) {
        self.formatter = formatter
        self.scope = scope
        self.escapesJSON = forTerminal
    }
    
    /// Turn a batch into output.
    ///
    /// - Parameter batch: Wire events (`Message` JSON), oldest first.
    /// - Returns: The output for the events that aren't the pipeline's own, one line each, in order.
    public func process(_ batch: [Data]) -> Data {
        let chunks: [Chunk]
        switch formatter {
        case .text(let text):
            chunks = [Chunk(batch[...], scope: scope) { event, decoder in
                let header = try decoder.decode(EventHeader.self, from: event)
                return (header, { Data(text.line(for: header).utf8) })
            }]
        case .jsonl(let encoders):
            let parts = Self.split(batch, into: batch.count >= Self.parallelThreshold ? encoders.count : 1)
            var encoded = [Chunk?](repeating: nil, count: parts.count)
            let (scope, escapes) = (scope, escapesJSON)
            encoded.withUnsafeMutableBufferPointer { encoded in
                DispatchQueue.concurrentPerform(iterations: parts.count) { index in
                    encoded[index] = Chunk(parts[index], scope: scope) { event, decoder in
                        let message = try decoder.decode(Message.self, from: event)
                        return (EventHeader(message), {
                            let line = encoders[index].line(for: message)
                            return escapes ? TerminalSafeText.json(line) : line
                        })
                    }
                }
            }
            encoders.forEach { $0.reset() }
            chunks = encoded.compactMap { $0 }
        }
        return chunks.reduce(into: Data()) { output, chunk in
            chunk.headers.forEach(meter.observe)
            written += chunk.headers.count - chunk.suppressed
            suppressed += chunk.suppressed
            unreadable += chunk.unreadable
            output.append(chunk.output)
        }
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
    /// What one formatter made of a run of a batch's events: every event's header, in order, for the meter, and the
    /// output for those that aren't the pipeline's own. Made on any thread.
    struct Chunk {
        /// Every event read, in order, suppressed or not.
        private(set) var headers: [EventHeader] = []
        /// The output for the events written.
        private(set) var output = Data()
        /// Events left out as the pipeline's own.
        private(set) var suppressed: Int = 0
        /// Events that couldn't be read.
        private(set) var unreadable: Int = 0
        
        /// Read and format a run of events.
        ///
        /// - Parameters:
        ///   - events: Wire events.
        ///   - scope: Which events are the pipeline's own.
        ///   - decode: Decodes an event into its header and a way to format it, which is only called for an event
        ///     that's written.
        init(_ events: ArraySlice<Data>, scope: PipelineScope,
             decode: (Data, JSONDecoder) throws -> (header: EventHeader, format: () -> Data)) {
            let decoder = JSONDecoder()
            for event in events {
                guard let decoded = try? decode(event, decoder) else {
                    unreadable += 1
                    continue
                }
                headers.append(decoded.header)
                if scope.suppresses(decoded.header) {
                    suppressed += 1
                } else {
                    output.append(decoded.format())
                }
            }
        }
    }
}

