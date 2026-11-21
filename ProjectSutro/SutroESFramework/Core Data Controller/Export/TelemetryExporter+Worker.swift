//
//  TelemetryExporter+Worker.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation
import CoreData
import os


// MARK: - Workers
extension TelemetryExporter {
    /// Fetches and encodes one batch at a time on its own context, pinned to the export's snapshot. Used by one thread
    /// at a time.
    /// What a worker made of one batch.
    struct Encoded {
        /// The records, joined by newlines.
        var json = Data()
        /// How many records there are.
        var count = 0
        /// Where each record ends in ``json``.
        var ends: [Int] = []
        /// What each record says of processes (``StreamSnapshots/Naming``), in the records' order.
        var namings: [StreamSnapshots.Naming?] = []
    }

    final class Worker {
        let context: NSManagedObjectContext
        private let pretty: Bool
        /// Writes JSONL records where it sorts keys as `JSONEncoder` does
        /// (``ProcessHelpers/eventToJSON(value:pretty:)`` otherwise).
        private let encoder: StreamingJSONEncoder?
        /// The indicators each record lists, its own.
        private let indicators: RecordIndicators?
        /// Events this worker couldn't encode in the current export.
        var unencodable = 0
        /// How many unencodable events each worker names in the log. Past that it only counts them.
        private static let namedLimit = 10
        private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "TelemetryExporter")
        
        /// - Parameters:
        ///   - context: Its own context.
        ///   - pretty: Pretty-printed JSON (`true`) or JSONL (`false`).
        ///   - indicators: The indicators each record lists, if any.
        init(context: NSManagedObjectContext, pretty: Bool, indicators: RecordIndicators?) {
            self.context = context
            self.pretty = pretty
            self.indicators = indicators
            encoder = !pretty && StreamingJSONEncoder.sortsKeysAsJSONEncoderDoes
                ? StreamingJSONEncoder(sortsKeys: true, escapesSlashes: false) : nil
        }
        
        /// Fetch a batch, fully loaded with every relationship its events encode, and encode its events in `batch`
        /// order: the events still in the store, each as `eventToJSON` writes it (`{}` for one it can't encode, see
        /// ``record(_:)``).
        ///
        /// - Parameters:
        ///   - batch: The events' object IDs.
        ///   - prefetch: Every to-one relationship an event encodes.
        /// - Returns: The records joined by newlines, how many there are, where each ends, and what each exec or
        ///   fork among them says of processes, by its place, or the error fetching them.
        func encode(_ batch: [NSManagedObjectID], prefetch: [String]) -> Result<Encoded, Error> {
            context.performAndWait {
                Result {
                    try autoreleasepool {
                        let request = ESMessage.request(where: NSPredicate(format: "self IN %@", batch), loaded: true)
                        request.relationshipKeyPathsForPrefetching = prefetch
                        let loaded = Dictionary(try context.fetch(request).map { ($0.objectID, $0) },
                                                uniquingKeysWith: { first, _ in first })
                        var encoded = Encoded()
                        for message in batch.compactMap({ loaded[$0] }) {
                            if encoded.count > 0 { encoded.json.append(0x0A) }
                            encoded.json.append(record(message))
                            encoded.namings.append(StreamSnapshots.Naming(message))
                            encoded.ends.append(encoded.json.count)
                            encoded.count += 1
                        }
                        /// Not reset(): that would also unpin the context from the snapshot.
                        context.refreshAllObjects()
                        return encoded
                    }
                }
            }
        }
        
        /// One event's record.
        ///
        /// An event that can't be encoded is logged by ID and type, counted, and written as `{}`. Dropping it would
        /// leave the file with fewer records than the export's total and the count it reports. Old exports wrote `{}`
        /// too.
        ///
        /// - Parameter message: The event.
        /// - Returns: Its JSON, or `{}`.
        private func record(_ message: ESMessage) -> Data {
            do {
                return try RecordIndicators.encoding(with: indicators) {
                    try encoder?.encode(message) ?? ProcessHelpers.eventJSON(message, pretty: pretty)
                }
            } catch {
                unencodable += 1
                if unencodable <= Self.namedLimit {
                    Self.logger.error("""
                        Event \(message.id.uuidString, privacy: .public) \
                        (\(message.es_event_type ?? String(message.event_type), privacy: .public)) couldn't be \
                        encoded and was written as {}: \(error.localizedDescription, privacy: .public)
                        """)
                }
                return Data("{}".utf8)
            }
        }
        
        /// Log how many events an export wrote as `{}`, if any.
        ///
        /// - Parameters:
        ///   - count: The events that couldn't be encoded.
        ///   - written: The events written.
        static func logUnencodable(_ count: Int, of written: Int) {
            guard count > 0 else { return }
            logger.fault("\(count) of \(written) exported events couldn't be encoded. Each was written as {}.")
        }
    }
}
