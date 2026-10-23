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
    /// Each event is inserted the way ``CoreDataController`` inserts one: with its instigator's token, its columns
    /// (``ESMessage/denormalize(from:)``), its place in the store, and batch 1. Then the events are saved and `body`
    /// runs on the context's queue.
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
                let event = ESMessage(from: message, insertIntoManagedObjectContext: context)
                event.insert_order = Int64(order)
                event.insert_batch = 1
                event.instigator_audit_token = message.process.audit_token_string
                event.denormalize(from: message)
                return event
            }
            try context.save()
            return try body(context, stored)
        }
    }
}


// MARK: - An event store on disk
extension XCTestCase {
    /// A store on disk holding events as Mac Monitor stores them, all saved in batch 1, in order. It's removed when the
    /// test ends.
    ///
    /// Each event is inserted the way ``CoreDataController`` inserts one (see ``withEventStore(_:_:)``).
    ///
    /// - Parameter messages: The events, in the order they reach the store.
    /// - Returns: The store.
    /// - Throws: The error loading the store or saving the events.
    func makeExportStore(_ messages: [Message]) throws -> NSPersistentContainer {
        let container = NSPersistentContainer(name: "SystemEvents", managedObjectModel: eventModel)
        let url = try makeTemporaryDirectory().appendingPathComponent("SystemEvents.sqlite")
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
                let stored = ESMessage(from: message, insertIntoManagedObjectContext: context)
                stored.insert_order = Int64(order)
                stored.insert_batch = 1
                stored.instigator_audit_token = message.process.audit_token_string
                stored.denormalize(from: message)
            }
            try context.save()
        }
        return container
    }
    
    /// Export every event of a store the way "Export all" does.
    ///
    /// - Parameters:
    ///   - container: The store.
    ///   - pretty: Pretty-printed JSON (`true`) or JSONL (`false`).
    ///   - source: Where the store's events come from.
    /// - Returns: The export, in a temporary folder, and the number of events written.
    /// - Throws: The export's error.
    func exportAll(_ container: NSPersistentContainer, pretty: Bool = false,
                   from source: CoreDataController.EventSource = .live) throws -> (url: URL, events: Int) {
        let url = try makeTemporaryDirectory().appendingPathComponent(pretty ? "trace.json" : "trace.jsonl")
        let exported = expectation(description: "exported")
        var result: Result<Int, Error>?
        TelemetryExporter(container: container, pretty: pretty).run(to: url, writeIfEmpty: true, choose: {
            try $0.allEvents(through: 1, from: source)
        }) {
            result = $0
            exported.fulfill()
        }
        wait(for: [exported], timeout: 30)
        return (url, try XCTUnwrap(result).get())
    }
}
