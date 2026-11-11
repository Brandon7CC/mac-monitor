//
//  ExportEncoder.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import CoreData


// MARK: - Export encoder
/// Encodes events the way Export telemetry > JSONL (lines) writes them, without an event store: `macmonitor`'s JSONL.
///
/// Each event becomes the same `ESMessage` the store keeps, in a context with no persistent store (so nothing is ever
/// saved), and is encoded as the export encodes it: with ``StreamingJSONEncoder`` where it sorts keys as this Mac's
/// `JSONEncoder` does (``StreamingJSONEncoder/sortsKeysAsJSONEncoderDoes``), which is several times quicker, and
/// otherwise, or pretty-printed, with ``ProcessHelpers/eventToJSON(value:pretty:)``. Either way each record is an
/// eslogger superset with the export's bytes. A JSONL record is one line. A pretty one spans lines. Every record here
/// ends with a newline, where an export's last record has none. It never touches `CoreDataController.shared`, the
/// user's caches, or their preferences.
///
/// **Threading:** not thread-safe. One per thread. Every call waits on its private-queue context.
public final class ExportEncoder {
    /// The event model, loaded once per process from the framework: Core Data complains when two copies of a model
    /// claim the same classes. The event store (``CoreDataController``) uses it too, and the app and the Security
    /// Extension don't bundle their own. `nil` if the framework's `SystemEvents.momd` is missing.
    public static let model: NSManagedObjectModel? = Bundle(for: ESMessage.self)
        .url(forResource: "SystemEvents", withExtension: "momd")
        .flatMap { NSManagedObjectModel(contentsOf: $0) }
    
    /// Holds each event's rows until ``reset()``.
    private let context: NSManagedObjectContext
    
    public let pretty: Bool
    /// The indicators each record lists: the verdicts each event carries, else these matched now.
    private let indicators: RecordIndicators
    /// Writes a record on one line where it sorts keys as `JSONEncoder` does, or `nil` to leave it to `JSONEncoder`.
    private let encoder: StreamingJSONEncoder?
    
    /// - Parameters:
    ///   - model: The event model, such as ``model``.
    ///   - pretty: Pretty-print each record.
    ///   - indicators: The indicators matched for an event that carries no verdicts, or `nil` to match none: each
    ///     record then lists the verdicts its event carries (``RecordIndicators/stored``), as `macmonitor stream`'s
    ///     do, and an event without them has no `indicators` key.
    public init(model: NSManagedObjectModel, pretty: Bool = false, indicators: [Indicator]? = nil) {
        self.pretty = pretty
        self.indicators = indicators.map(RecordIndicators.init) ?? .stored
        encoder = !pretty && StreamingJSONEncoder.sortsKeysAsJSONEncoderDoes
            ? StreamingJSONEncoder(sortsKeys: true, escapesSlashes: false) : nil
        context = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
        context.persistentStoreCoordinator = NSPersistentStoreCoordinator(managedObjectModel: model)
        context.undoManager = nil
    }
    
    /// An event's export record.
    ///
    /// - Parameter message: The event, decoded from the wire.
    /// - Returns: The record's JSON and a newline.
    public func line(for message: Message) -> Data {
        context.performAndWait {
            autoreleasepool {
                let row = ESMessage(from: message, insertIntoManagedObjectContext: context)
                var line = RecordIndicators.encoding(with: indicators) { record(row) }
                line.append(0x0A)
                return line
            }
        }
    }
    
    /// An event's record, as ``ProcessHelpers/eventToJSON(value:pretty:)`` writes it: `{}` for one that can't be
    /// encoded.
    ///
    /// - Parameter row: The event, in ``context``.
    /// - Returns: The record's JSON.
    private func record(_ row: ESMessage) -> Data {
        if let encoder, let json = try? encoder.encode(row) { return json }
        return Data(ProcessHelpers.eventToJSON(value: row, pretty: pretty).utf8)
    }

    /// Forget the rows inserted so far. Call after each batch, so memory stays flat.
    public func reset() {
        context.performAndWait { context.reset() }
    }
}
