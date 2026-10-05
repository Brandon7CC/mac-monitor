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
