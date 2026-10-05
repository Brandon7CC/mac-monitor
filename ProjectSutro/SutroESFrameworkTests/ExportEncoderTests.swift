//
//  ExportEncoderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Export encoder
/// Pins `macmonitor`'s JSONL to Mac Monitor's export: for real events, a record is byte for byte what Export
/// telemetry ▸ JSONL (lines) writes from the event store, also after the trip over the wire, and many events through
/// one encoder never leak into each other.
final class ExportEncoderTests: XCTestCase {
    /// A store on disk holding the events, saved as a recording saves them, in their order.
    ///
    /// - Parameter messages: The events.
    /// - Returns: The store.
    /// - Throws: The error loading the store or saving the events.
    private func makeStore(_ messages: [Message]) throws -> NSPersistentContainer {
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
    
    /// Export a store as Export telemetry ▸ JSONL (lines) does, in the order the events were saved.
    ///
    /// - Parameter container: The store.
    /// - Returns: The file's bytes.
    /// - Throws: The export's error.
    private func exportJSONL(_ container: NSPersistentContainer) throws -> Data {
        let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
        let exported = expectation(description: "exported")
        var result: Result<Int, Error>?
        let source = CoreDataController.EventSource.trace(URL(fileURLWithPath: "/tmp/trace.jsonl"))
        TelemetryExporter(container: container, pretty: false).run(to: url, writeIfEmpty: true, choose: {
            try $0.allEvents(through: 1, from: source)
        }) {
            result = $0
            exported.fulfill()
        }
        wait(for: [exported], timeout: 10)
        _ = try XCTUnwrap(result).get()
        return try Data(contentsOf: url)
    }
    
    /// Every fixture's events, encoded one per line, are byte for byte the export of the same events saved in a store
    /// on disk (which joins records with newlines and ends without one).
    ///
    /// - Throws: The error reading a fixture, building the store, or exporting it.
    func testRecordsMatchTheStoresExport() throws {
        let messages = try allFixtureMessages()
        let encoder = ExportEncoder(model: eventModel)
        var lines = messages.reduce(into: Data()) { $0.append(encoder.line(for: $1)) }
        XCTAssertEqual(lines.removeLast(), 0x0A)
        XCTAssertEqual(String(decoding: lines, as: UTF8.self),
                       String(decoding: try exportJSONL(try makeStore(messages)), as: UTF8.self))
    }
    
    /// After the trip over the wire (the capture lane's encoder, then `JSONDecoder`), a record is still exactly the
    /// export of the original event, and ends in exactly one newline.
    ///
    /// - Throws: The error reading a fixture, or encoding or decoding an event.
    func testTheWireChangesNothing() throws {
        let encoder = ExportEncoder(model: eventModel)
        for message in try allFixtureMessages() {
            let received = try JSONDecoder().decode(Message.self, from: try wire(message))
            let line = String(decoding: encoder.line(for: received), as: UTF8.self)
            XCTAssertEqual(line, exportText(message) + "\n", message.es_event_type)
            XCTAssertFalse(line.dropLast().contains("\n"))
        }
    }
    
    /// Many events through one encoder, reset after each batch as the pipeline does, stay byte for byte what a fresh
    /// encoder writes: no rows leak from one event or batch into the next.
    ///
    /// - Throws: The error reading a fixture.
    func testManyEventsDontLeakIntoEachOther() throws {
        let messages = try allFixtureMessages()
        let expected = messages.map { ExportEncoder(model: eventModel).line(for: $0) }
        let encoder = ExportEncoder(model: eventModel)
        for round in 0..<(2_000 / messages.count) {
            for (index, message) in messages.enumerated() {
                XCTAssertEqual(encoder.line(for: message), expected[index], "round \(round), event \(index)")
            }
            if round % 3 == 2 { encoder.reset() }
        }
    }
}
