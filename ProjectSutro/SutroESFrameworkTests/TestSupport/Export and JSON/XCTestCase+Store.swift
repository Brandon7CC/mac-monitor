//
//  XCTestCase+Store.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - An event store in memory
extension XCTestCase {
    /// Store events as Mac Monitor does, in a store of their own in memory, and read them back.
    ///
    /// Each event is inserted the way ``CoreDataController`` inserts one (``ESMessage/init(storing:order:batch:in:)``),
    /// in batch 1. Then the events are saved and `body` runs on the context's queue.
    ///
    /// - Parameters:
    ///   - messages: The events, in order.
    ///   - body: Reads the store, given the context the events were saved in and the stored events, in order.
    /// - Returns: What `body` returns.
    /// - Throws: The error adding the store or saving the events, or what `body` throws.
    func withEventStore<T>(_ messages: [Message],
                           _ body: (NSManagedObjectContext, [ESMessage]) throws -> T) throws -> T {
        let coordinator = NSPersistentStoreCoordinator(managedObjectModel: eventModel)
        try coordinator.addPersistentStore(ofType: NSInMemoryStoreType, configurationName: nil, at: nil)
        let context = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
        context.persistentStoreCoordinator = coordinator
        return try context.performAndWait {
            let stored = messages.enumerated().map { order, message in
                ESMessage(storing: message, order: Int64(order), batch: 1, in: context)
            }
            try context.save()
            return try body(context, stored)
        }
    }
}


// MARK: - An event store on disk
extension XCTestCase {
    /// A store holding events as Mac Monitor stores them, all saved in batch 1, in order. It's removed when the test
    /// ends.
    ///
    /// Each event is inserted the way ``CoreDataController`` inserts one (see ``withEventStore(_:_:)``).
    ///
    /// - Parameters:
    ///   - messages: The events, in the order they reach the store.
    ///   - url: Where the store keeps its file: a temporary folder by default, or `/dev/null` for a store in memory.
    /// - Returns: The store.
    /// - Throws: The error loading the store or saving the events.
    func makeExportStore(_ messages: [Message], at url: URL? = nil) throws -> NSPersistentContainer {
        let container = NSPersistentContainer(name: "SystemEvents", managedObjectModel: eventModel)
        let url = try url ?? makeTemporaryDirectory().appendingPathComponent("SystemEvents.sqlite")
        container.persistentStoreDescriptions = [NSPersistentStoreDescription(url: url)]
        var loadError: Error?
        container.loadPersistentStores { _, error in loadError = error }
        if let loadError { throw loadError }
        addTeardownBlock {
            container.persistentStoreCoordinator.persistentStores.forEach {
                try? container.persistentStoreCoordinator.remove($0)
            }
        }
        
        let context = container.newBackgroundContext()
        try context.performAndWait {
            for (order, message) in messages.enumerated() {
                ESMessage(storing: message, order: Int64(order), batch: 1, in: context)
            }
            try context.save()
        }
        return container
    }
    
    /// Every event of a store, in file order, through `eventToJSON`, joined by newlines: what an export writes.
    ///
    /// - Parameter container: The store.
    /// - Returns: The file's text.
    /// - Throws: The error fetching the events.
    func expectedExport(of container: NSPersistentContainer) throws -> String {
        let context = container.newBackgroundContext()
        return try context.performAndWait {
            let request = ESMessage.request(sortedBy: [NSSortDescriptor(key: "mach_time", ascending: true),
                                                       NSSortDescriptor(key: "insert_order", ascending: true)])
            return try context.fetch(request).map { ProcessHelpers.eventToJSON(value: $0) }.joined(separator: "\n")
        }
    }
    
    /// Export every event of a store, and wait until the export has finished.
    ///
    /// - Parameters:
    ///   - exporter: The export, pinned or not.
    ///   - url: The destination.
    ///   - source: Where the store's events come from.
    ///   - timeout: How long the export may take.
    ///   - progress: Called with each report the export makes.
    /// - Returns: The number of events written.
    /// - Throws: The export's error, or an `XCTest` failure if it didn't finish in time.
    func run(_ exporter: TelemetryExporter, to url: URL, from source: CoreDataController.EventSource = .live,
             timeout: TimeInterval = 120,
             progress: @escaping (TelemetryExporter.Progress) -> Void = { _ in }) throws -> Int {
        let exported = expectation(description: "exported")
        var result: Result<Int, Error>?
        exporter.run(to: url, writeIfEmpty: true, choose: { try $0.allEvents(through: 1, from: source) },
                     progress: progress) {
            result = $0
            exported.fulfill()
        }
        wait(for: [exported], timeout: timeout)
        return try XCTUnwrap(result).get()
    }
    
    /// Export every event of a store the way "Export all" does.
    ///
    /// - Parameters:
    ///   - container: The store.
    ///   - pretty: Pretty-printed JSON (`true`) or JSONL (`false`).
    ///   - source: Where the store's events come from.
    ///   - timeout: How long the export may take.
    /// - Returns: The export, in a temporary folder, and the number of events written.
    /// - Throws: The export's error.
    func exportAll(_ container: NSPersistentContainer, pretty: Bool = false,
                   from source: CoreDataController.EventSource = .live,
                   timeout: TimeInterval = 30) throws -> (url: URL, events: Int) {
        let url = try makeTemporaryDirectory().appendingPathComponent(pretty ? "trace.json" : "trace.jsonl")
        let exporter = TelemetryExporter(container: container, pretty: pretty)
        return (url, try run(exporter, to: url, from: source, timeout: timeout))
    }
}
