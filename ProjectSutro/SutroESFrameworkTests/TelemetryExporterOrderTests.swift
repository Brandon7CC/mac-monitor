//
//  TelemetryExporterOrderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Export order
/// Pins the order "Export all" writes events in: a live recording's by `mach_time`, since the capture clients' events
/// reach the store in the order they were handled, and an opened trace's in its file order.
final class TelemetryExporterOrderTests: XCTestCase {
    /// Each stored event's `mach_time`, in the order the events reached the store: a process event, then a file event
    /// from before it that its busy client handed over late, two at the same time, and a memory event from before all.
    private let arrivals: [Int64] = [300, 100, 200, 200, 50]
    
    /// A store on disk holding one event per entry of ``arrivals``, in that order, all saved in batch 1. Each event's
    /// `global_seq_num` is its `insert_order`, so the export shows where it came from.
    ///
    /// - Returns: The store.
    /// - Throws: The error loading the store, reading the fixture, or saving the events.
    private func makeStore() throws -> NSPersistentContainer {
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
        
        let exit = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        let context = container.newBackgroundContext()
        try context.performAndWait {
            for (order, machTime) in arrivals.enumerated() {
                var message = exit
                message.id = UUID()
                message.mach_time = machTime
                message.global_seq_num = order
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
    
    /// Export every event the way "Export all" does, as JSONL.
    ///
    /// - Parameters:
    ///   - container: The store.
    ///   - source: Where the store's events come from.
    /// - Returns: Each exported event's `global_seq_num` (its `insert_order`), in file order.
    /// - Throws: The export's error, or an `XCTest` failure if a line isn't an event.
    private func exportAll(_ container: NSPersistentContainer,
                           from source: CoreDataController.EventSource) throws -> [Int] {
        let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
        let exported = expectation(description: "exported")
        var result: Result<Int, Error>?
        TelemetryExporter(container: container, pretty: false).run(to: url, writeIfEmpty: true, choose: {
            try $0.allEvents(through: 1, from: source)
        }) {
            result = $0
            exported.fulfill()
        }
        wait(for: [exported], timeout: 10)
        XCTAssertEqual(try XCTUnwrap(result).get(), arrivals.count)
        return try String(contentsOf: url, encoding: .utf8).split(separator: "\n").map { line in
            let record = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
            return try XCTUnwrap(record["global_seq_num"] as? Int)
        }
    }
    
    /// A live recording is exported by `mach_time`, ties in the order the events reached the store.
    ///
    /// - Throws: The error building the store or exporting it.
    func testLiveRecordingIsExportedByMachTime() throws {
        XCTAssertEqual(try exportAll(try makeStore(), from: .live), [4, 1, 2, 3, 0])
    }
    
    /// An opened trace is exported in its file order, which is the order its events reached the store.
    ///
    /// - Throws: The error building the store or exporting it.
    func testOpenedTraceKeepsItsFileOrder() throws {
        let trace = CoreDataController.EventSource.trace(URL(fileURLWithPath: "/tmp/trace.jsonl"))
        XCTAssertEqual(try exportAll(try makeStore(), from: trace), [0, 1, 2, 3, 4])
    }
}
