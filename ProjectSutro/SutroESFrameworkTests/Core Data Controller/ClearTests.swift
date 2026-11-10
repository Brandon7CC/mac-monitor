//
//  ClearTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/25/26.
//

import XCTest
import CoreData
import SQLite3
@testable import SutroESFramework


// MARK: - Clear
/// Pins how a Clear empties the event store: by swapping in a new, empty store, which takes a fraction of a second at
/// any size, so a recording or a trace that starts right after carries on at once. While an export reads the store, the
/// rows are deleted instead, and the export still writes every event it started with. A Clear also keeps out events
/// recorded before it, and a trace keeps out every recorded event until the next Clear.
final class ClearTests: XCTestCase {
    /// Events of every type, made up as happening at one time: now by default, so a Clear made before now discards
    /// none of them.
    ///
    /// - Parameters:
    ///   - count: How many.
    ///   - date: When they happened, as the Security Extension stamps it (`message_darwin_time`).
    /// - Returns: The events.
    /// - Throws: The error making up an event.
    private func events(_ count: Int, at date: Date = Date()) throws -> [Message] {
        let corpus = try SyntheticCorpus.records().map(\.message)
        return (0..<count).map { index in
            var message = corpus[index % corpus.count]
            message.id = UUID()
            message.message_darwin_time = date
            return message
        }
    }

    /// Record events, and wait until they're saved.
    ///
    /// - Parameters:
    ///   - messages: The events.
    ///   - store: The event store.
    /// - Returns: The events the store kept, by ID.
    @discardableResult
    private func record(_ messages: [Message], in store: CoreDataController) -> Set<UUID> {
        let saved = expectation(description: "saved")
        var kept: Set<UUID> = []
        store.insertSystemEvents(messages: messages, watching: Set(messages.map(\.id))) {
            kept = $0
            saved.fulfill()
        }
        wait(for: [saved], timeout: 60)
        return kept
    }

    /// Clear, and wait until the Clear has finished.
    ///
    /// - Parameter store: The event store.
    private func clear(_ store: CoreDataController) {
        let cleared = expectation(forNotification: CoreDataController.eventsDidClear, object: store)
        store.clearSystemEvents()
        wait(for: [cleared], timeout: 120)
    }

    /// The store's identity, which a new store doesn't share.
    ///
    /// - Parameter store: The event store.
    /// - Returns: Each persistent store's identifier.
    private func identifiers(of store: CoreDataController) -> [String] {
        store.container.persistentStoreCoordinator.persistentStores.map(\.identifier)
    }

    /// The indexes SQLite keeps on `ZESEVENTTYPE`, read from the store's file.
    ///
    /// - Parameter store: The event store.
    /// - Returns: Their names.
    private func eventTypeIndexes(of store: CoreDataController) throws -> [String] {
        var database: OpaquePointer?
        defer { sqlite3_close(database) }
        let path = try XCTUnwrap(store.storeURL).path
        XCTAssertEqual(sqlite3_open_v2(path, &database, SQLITE_OPEN_READONLY, nil), SQLITE_OK)
        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        let query = "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'ZESEVENTTYPE'"
        XCTAssertEqual(sqlite3_prepare_v2(database, query, -1, &statement, nil), SQLITE_OK)
        var names: [String] = []
        while sqlite3_step(statement) == SQLITE_ROW { names.append(String(cString: sqlite3_column_text(statement, 0))) }
        return names
    }

    /// A new store, and the one each Clear swaps in, has none of the 51 indexes Core Data makes for `ESEventType`'s
    /// relationships, which nothing looks up and every save updated; events still save and read back.
    func testStoresDropTheEventTypeIndexes() throws {
        let store = CoreDataController(model: eventModel)
        XCTAssertEqual(try eventTypeIndexes(of: store), [], "A new store kept them")
        record(try events(200), in: store)
        clear(store)
        XCTAssertEqual(try eventTypeIndexes(of: store), [], "The store a Clear swapped in kept them")
        record(try events(200), in: store)
        XCTAssertEqual(store.eventCount, 200)
        let context = store.container.newBackgroundContext()
        try context.performAndWait {
            let request = ESMessage.request()
            let model = store.container.managedObjectModel
            request.relationshipKeyPathsForPrefetching = ESMessage.recordPrefetchKeyPaths(in: model)
            XCTAssertTrue(try context.fetch(request).allSatisfy { $0.event.objectID.persistentStore != nil })
        }
    }

    /// A Clear swaps in a new, empty store rather than deleting every row, and keeps the events recorded after it.
    func testClearReplacesTheStore() throws {
        let store = CoreDataController(model: eventModel)
        record(try events(1_000), in: store)
        XCTAssertEqual(store.eventCount, 1_000)
        let before = identifiers(of: store)

        clear(store)
        XCTAssertNotEqual(identifiers(of: store), before, "The Clear kept the store")
        XCTAssertEqual(store.eventCount, 0)

        record(try events(10), in: store)
        XCTAssertEqual(store.eventCount, 10)
    }

    /// A Clear while an export reads the store deletes its rows instead of taking the store away, and the export,
    /// pinned to the store as it started, still writes every event.
    func testClearDuringAnExportDeletesInstead() throws {
        let store = CoreDataController(model: eventModel)
        record(try events(2_000), in: store)
        let before = identifiers(of: store)
        let expected = try expectedExport(of: store.container)

        let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
        let exported = expectation(description: "exported")
        var result: Result<Int, Error>?
        store.exportEvents(to: url, jsonl: true) {
            result = $0
            exported.fulfill()
        }
        clear(store)
        wait(for: [exported], timeout: 120)

        XCTAssertEqual(try XCTUnwrap(result).get(), 2_000)
        XCTAssertTrue(String(decoding: try Data(contentsOf: url), as: UTF8.self) == expected,
                      "The export isn't the store as it was when it started")
        XCTAssertEqual(identifiers(of: store), before, "The Clear took the store from under the export")
        XCTAssertEqual(store.eventCount, 0)
    }

    // MARK: What a Clear keeps out

    /// Events that happened before a Clear but reach the store after it, as events still on their way from the
    /// Security Extension do, are discarded, and those that happened after it are kept. The cutoff is the Clear's call:
    /// an event from just before it goes, one from as it returned stays.
    func testEventsFromBeforeAClearAreDiscarded() throws {
        let store = CoreDataController(model: eventModel)
        let cleared = expectation(forNotification: CoreDataController.eventsDidClear, object: store)
        let calling = Date()
        store.clearSystemEvents()
        let returned = Date()
        let older = try events(100, at: calling.addingTimeInterval(-0.001))
        let newer = try events(100, at: returned)
        /// Queued behind the Clear, interleaved, so neither half is kept or dropped by where it is in the batch.
        let kept = record(zip(older, newer).flatMap { [$0, $1] }, in: store)
        wait(for: [cleared], timeout: 120)

        XCTAssertEqual(kept, Set(newer.map(\.id)), "The store didn't keep exactly the events from after the Clear")
        XCTAssertEqual(store.eventCount, newer.count)
    }

    /// While a trace is open, no recorded event joins it, however recent, whether it arrives as the trace is read or
    /// after. The Clear that closes the trace lets recording fill the store again.
    func testATraceKeepsOutRecordedEvents() throws {
        let store = CoreDataController(model: eventModel)
        let url = try esloggerTrace(10)
        let opened = expectation(description: "opened")
        var summary: TraceImporter.Summary?
        store.openTrace(at: url) { summary = $0; opened.fulfill() }
        /// Dated a minute ahead, so a cutoff at the Clear's time would keep them.
        let duringImport = record(try events(50, at: Date().addingTimeInterval(60)), in: store)
        wait(for: [opened], timeout: 60)
        let afterImport = record(try events(50, at: Date().addingTimeInterval(60)), in: store)

        XCTAssertEqual(duringImport, [], "Recorded events joined the trace as it was read")
        XCTAssertEqual(afterImport, [], "Recorded events joined the trace once it was read")
        XCTAssertEqual(try XCTUnwrap(summary).saved, 10)
        XCTAssertEqual(try storedMachTimes(in: store), Array(0..<10), "The store holds more than the trace")

        clear(store)
        let live = try events(20)
        XCTAssertEqual(record(live, in: store), Set(live.map(\.id)), "Recording didn't resume after the trace closed")
        XCTAssertEqual(store.eventCount, live.count)
    }
}
