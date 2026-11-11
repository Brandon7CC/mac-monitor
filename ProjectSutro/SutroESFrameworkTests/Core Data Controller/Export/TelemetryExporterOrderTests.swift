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
/// Pins which events an export writes and in what order. "Export all" writes a live recording's by `mach_time`, since
/// the capture clients' events reach the store in the order they were handled, and an opened trace's in its file order,
/// up to the batch saved when it started. A selection is written by `mach_time`, ties in the order it lists them, once
/// each, and only when the store has some of them.
final class TelemetryExporterOrderTests: XCTestCase {
    /// Each stored event's `mach_time`, in the order the events reached the store: a process event, then a file event
    /// from before it that its busy client handed over late, two at the same time, and a memory event from before all.
    private let arrivals: [Int64] = [300, 100, 200, 200, 50]

    /// A store on disk holding one event per entry of ``arrivals``, in that order, all saved in batch 1. Each event's
    /// `global_seq_num` is its `insert_order`, so the export shows where it came from.
    ///
    /// - Returns: The store, and its events' IDs in ``arrivals`` order.
    /// - Throws: The error loading the store, reading the fixture, or saving the events.
    private func makeStore() throws -> (container: NSPersistentContainer, ids: [UUID]) {
        let exit = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        let messages = arrivals.enumerated().map { order, machTime in
            var message = exit
            message.id = UUID()
            message.mach_time = machTime
            message.global_seq_num = order
            return message
        }
        return (try makeExportStore(messages), messages.map(\.id))
    }

    /// Export events as JSONL.
    ///
    /// - Parameters:
    ///   - container: The store.
    ///   - source: Where the store's events come from.
    ///   - writeIfEmpty: Write the file when no events are chosen.
    ///   - choose: Chooses the events: every event saved by batch 1 unless given, as "Export all" does.
    /// - Returns: Each exported event's `global_seq_num` (its `insert_order`), in file order.
    /// - Throws: The export's error, or an `XCTest` failure if a line isn't an event or the count reported is off.
    private func exportedOrder(_ container: NSPersistentContainer, from source: CoreDataController.EventSource = .live,
                               writeIfEmpty: Bool = true,
                               choose: ((TelemetryExporter) throws -> [NSManagedObjectID])? = nil) throws -> [Int] {
        let url = try makeTemporaryDirectory().appendingPathComponent("trace.jsonl")
        let exporter = TelemetryExporter(container: container, pretty: false)
        let written = try run(exporter, to: url, from: source, writeIfEmpty: writeIfEmpty, choose: choose, timeout: 60)
        let order = try String(contentsOf: url, encoding: .utf8).split(separator: "\n").map { line in
            let record = try jsonObject(Data(line.utf8))
            return try XCTUnwrap(record["global_seq_num"] as? Int)
        }
        XCTAssertEqual(written, order.count, "The export reported another count than it wrote")
        return order
    }

    /// Export through Mac Monitor's store, as the toolbar and the event table's menu do, and wait until it's done.
    ///
    /// - Parameters:
    ///   - selection: The selected events' IDs, or `nil` for the full trace.
    ///   - store: The event store.
    ///   - url: The destination.
    /// - Returns: The number of events written.
    /// - Throws: The export's error.
    private func export(_ selection: [UUID]?, of store: CoreDataController, to url: URL) throws -> Int {
        let exported = expectation(description: "exported")
        var result: Result<Int, Error>?
        store.exportEvents(selection, to: url, jsonl: true) { result = $0; exported.fulfill() }
        wait(for: [exported], timeout: 60)
        return try XCTUnwrap(result).get()
    }

    // MARK: Export all

    /// A live recording is exported by `mach_time`, ties in the order the events reached the store.
    func testLiveRecordingIsExportedByMachTime() throws {
        XCTAssertEqual(try exportedOrder(try makeStore().container, from: .live), [4, 1, 2, 3, 0])
    }

    /// An opened trace is exported in its file order, which is the order its events reached the store.
    func testOpenedTraceKeepsItsFileOrder() throws {
        let trace = CoreDataController.EventSource.trace(URL(fileURLWithPath: "/tmp/trace.jsonl"))
        XCTAssertEqual(try exportedOrder(try makeStore().container, from: trace), [0, 1, 2, 3, 4])
    }

    /// "Export all" writes the events saved up to its batch and none saved after, wherever they would sort, live or
    /// from a trace.
    func testAnExportStopsAtItsBatch() throws {
        let container = try makeStore().container
        let exit = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        let context = container.newBackgroundContext()
        /// Batch 2: one event among batch 1's by `mach_time`, and one before them all.
        try context.performAndWait {
            for (order, machTime) in [(5, Int64(150)), (6, Int64(25))] {
                var message = exit
                (message.id, message.mach_time, message.global_seq_num) = (UUID(), machTime, order)
                ESMessage(storing: message, order: Int64(order), batch: 2, in: context)
            }
            try context.save()
        }
        let trace = CoreDataController.EventSource.trace(URL(fileURLWithPath: "/tmp/trace.jsonl"))
        let cases: [(CoreDataController.EventSource, through1: [Int], through2: [Int])] = [
            (.live, [4, 1, 2, 3, 0], [6, 4, 1, 5, 2, 3, 0]),
            (trace, [0, 1, 2, 3, 4], [0, 1, 2, 3, 4, 5, 6]),
        ]
        for (source, through1, through2) in cases {
            XCTAssertEqual(try exportedOrder(container, from: source) { try $0.allEvents(through: 1, from: source) },
                           through1, "\(source)")
            XCTAssertEqual(try exportedOrder(container, from: source) { try $0.allEvents(through: 2, from: source) },
                           through2, "\(source)")
        }
    }

    // MARK: Selections

    /// A selection is exported by `mach_time`, ties in the order it lists them (not the order they reached the store),
    /// each event once at its first place, whatever IDs the store doesn't have. Its IDs are looked up
    /// ``TelemetryExporter/lookupSize`` at a time, and events from different lookups sort together.
    func testASelectionIsExportedByMachTimeTiesInSelectionOrder() throws {
        let (container, ids) = try makeStore()
        let unknown = (0..<TelemetryExporter.lookupSize).map { _ in UUID() }
        /// Event 3 first, in the first lookup, and again in the second, with events 2, 1 and 0. Event 4 isn't selected.
        let selection = [ids[3]] + unknown + [ids[2], ids[1], ids[3], ids[0]]
        let order = try exportedOrder(container, writeIfEmpty: false) { try $0.events(withIDs: selection) }
        XCTAssertEqual(order, [1, 3, 2, 0])
    }

    /// A selection the store has none of writes no file, and leaves a file already there as it was, though the store
    /// holds other events, which the full trace writes. The full trace of an empty store is still written, empty.
    func testAnEmptySelectionWritesNoFile() throws {
        let store = CoreDataController(model: eventModel)
        let exit = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        let recorded = (0..<3).map { _ in var message = exit; message.id = UUID(); return message }
        let saved = expectation(description: "recorded")
        store.insertSystemEvents(messages: recorded, watching: []) { _ in saved.fulfill() }
        wait(for: [saved], timeout: 60)
        XCTAssertEqual(store.eventCount, recorded.count)

        let folder = try makeTemporaryDirectory()
        let selection = folder.appendingPathComponent("selection.jsonl")
        try Data("kept".utf8).write(to: selection)
        XCTAssertEqual(try export([UUID(), UUID()], of: store, to: selection), 0)
        XCTAssertEqual(try export([], of: store, to: selection), 0)
        XCTAssertEqual(try Data(contentsOf: selection), Data("kept".utf8), "An empty selection replaced the file")

        let unwritten = folder.appendingPathComponent("unwritten.jsonl")
        XCTAssertEqual(try export([UUID()], of: store, to: unwritten), 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: unwritten.path), "An empty selection wrote a file")

        let full = folder.appendingPathComponent("trace.jsonl")
        XCTAssertEqual(try export(nil, of: store, to: full), recorded.count)
        let lines = try String(contentsOf: full, encoding: .utf8).split(separator: "\n")
        XCTAssertEqual(lines.count, recorded.count, "The full trace didn't write the recorded events")

        let empty = folder.appendingPathComponent("empty.jsonl")
        XCTAssertEqual(try export(nil, of: CoreDataController(model: eventModel), to: empty), 0)
        XCTAssertEqual(try Data(contentsOf: empty), Data(), "The full trace of an empty store wasn't written empty")
    }
}
