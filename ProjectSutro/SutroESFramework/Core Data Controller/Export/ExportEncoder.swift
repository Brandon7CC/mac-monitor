//
//  ExportEncoder.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import CoreData


// MARK: - Export encoder
/// Encodes events the way Export telemetry ▸ JSONL (lines) writes them, without an event store: `macmonitor`'s JSONL.
///
/// Each event becomes the same `ESMessage` the store keeps, in a context with no persistent store (so nothing is ever
/// saved), and is encoded with the same ``ProcessHelpers/eventToJSON(value:pretty:)``: one record per line, an
/// eslogger superset. It never touches `CoreDataController.shared`, the user's caches, or their preferences.
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
    
    /// - Parameters:
    ///   - model: The event model, such as ``model``.
    ///   - pretty: Pretty-print each record.
    public init(model: NSManagedObjectModel, pretty: Bool = false) {
        self.pretty = pretty
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
                let json = ProcessHelpers.eventToJSON(value: row, pretty: pretty)
                var line = Data(json.utf8)
                line.append(0x0A)
                return line
            }
        }
    }
    
    /// Forget the rows inserted so far. Call after each batch, so memory stays flat.
    public func reset() {
        context.performAndWait { context.reset() }
    }
}
