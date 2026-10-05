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
/// saved), and is encoded with the same ``ProcessHelpers/eventToJSON(value:)``: one record per line, an eslogger
/// superset. It never touches `CoreDataController.shared`, the user's caches, or their preferences.
///
/// **Threading:** not thread-safe; one per thread. Every call waits on its private-queue context.
public final class ExportEncoder {
    /// The event model, loaded once per process from the framework: Core Data complains when two copies of a model
    /// claim the same classes. `nil` if the framework's `SystemEvents.momd` is missing.
    public static let model: NSManagedObjectModel? = Bundle(for: ESMessage.self)
        .url(forResource: "SystemEvents", withExtension: "momd")
        .flatMap { NSManagedObjectModel(contentsOf: $0) }
    
    /// Holds each event's rows until ``reset()``.
    private let context: NSManagedObjectContext
    
    /// - Parameter model: The event model, such as ``model``.
    public init(model: NSManagedObjectModel) {
        context = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
        context.persistentStoreCoordinator = NSPersistentStoreCoordinator(managedObjectModel: model)
        context.undoManager = nil
    }
    
    /// An event's export record.
    ///
    /// - Parameter message: The event, decoded from the wire.
    /// - Returns: The record's JSON followed by a newline.
    public func line(for message: Message) -> Data {
        context.performAndWait {
            autoreleasepool {
                let row = ESMessage(from: message, insertIntoManagedObjectContext: context)
                var line = Data(ProcessHelpers.eventToJSON(value: row).utf8)
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
