//
//  TraceImporterSummaryTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import CoreData
import os
@testable import SutroESFramework


// MARK: - What an import reports
/// Pins what ``TraceImporter`` reports for a whole file, through
/// ``CoreDataController/openTrace(at:progress:completion:)`` on small traces: the records it skips and where the first
/// one is, the event types it counts by name and where it stops naming them, and how reading ends when it's stopped,
/// when a Clear closes the trace, and when a save fails. It also pins how much of a file
/// ``TraceImporter/preflight(_:)`` reads before turning it away.
final class TraceImporterSummaryTests: XCTestCase {
    /// Events in the traces that are stopped, closed or cut short: ten batches, so reading is still going when the
    /// first batch is saved.
    private static let longTrace = 10 * TraceImporter.batchSize

    /// eslogger's exit event with an event of another type in its place, one Mac Monitor doesn't have.
    ///
    /// - Parameters:
    ///   - name: eslogger's name for the type.
    ///   - exit: The exit fixture's object.
    /// - Returns: The record, as a line.
    /// - Throws: The error serializing it.
    private func unsupported(_ name: String, in exit: [String: Any]) throws -> String {
        var record = exit
        record["event"] = [name: [String: Any]()]
        return String(decoding: try JSONSerialization.data(withJSONObject: record), as: UTF8.self)
    }

    /// Run `body` on the store's queue as it announces its first saved batch (``CoreDataController/eventsInserted``),
    /// before the importer hears the batch is saved.
    ///
    /// - Parameters:
    ///   - store: The event store.
    ///   - body: What to do then.
    /// - Returns: How many batches were announced, read once the test is done with the store.
    private func onFirstSave(of store: CoreDataController, _ body: @escaping () -> Void) -> () -> Int {
        let announced = OSAllocatedUnfairLock(initialState: 0)
        let observer = NotificationCenter.default.addObserver(forName: CoreDataController.eventsInserted,
                                                              object: store, queue: nil) { _ in
            if announced.withLock({ count in count += 1; return count }) == 1 { body() }
        }
        addTeardownBlock { NotificationCenter.default.removeObserver(observer) }
        return { announced.withLock { $0 } }
    }

    /// Run `body` with ``TraceImporter/pipelined`` on, then off.
    ///
    /// - Parameter body: The test, given whether the import is pipelined.
    /// - Throws: What `body` throws.
    private func eachPipeline(_ body: (Bool) throws -> Void) rethrows {
        let previous = TraceImporter.pipelined
        defer { TraceImporter.pipelined = previous }
        for pipelined in [true, false] {
            TraceImporter.pipelined = pipelined
            try body(pipelined)
        }
    }

    // MARK: Skipped records

    /// Records that aren't events are skipped and counted, and the first one's line is reported even when a later line
    /// is counted first: a line that isn't JSON is counted as it's read, a record that isn't an event only once its
    /// batch is decoded. A type Mac Monitor doesn't have is counted by name, not skipped, and the summary that ends
    /// `log show --style ndjson` is neither.
    func testSkippedRecordsAreCountedFromTheFirst() throws {
        let exit = try fixtureObject("eslogger-exit.jsonl")
        var timeless = exit
        timeless["time"] = nil
        let lines = [
            try esloggerExitLine(0, of: exit),
            try esloggerExitLine(1, of: exit),
            #"{"process":{},"note":"not an event"}"#,
            try esloggerExitLine(2, of: exit),
            String(decoding: try JSONSerialization.data(withJSONObject: timeless), as: UTF8.self),
            "not JSON at all",
            try unsupported("bogus", in: exit),
            try esloggerExitLine(3, of: exit),
            #"{"finished":1,"count":8}"#,
        ]
        let url = try temporaryFile(containing: lines.joined(separator: "\n"), named: "trace.jsonl")
        let store = CoreDataController(model: eventModel)
        let summary = try openTrace(url, in: store)

        XCTAssertNil(summary.error)
        XCTAssertNil(summary.stoppedAt)
        XCTAssertEqual(summary.saved, 4)
        XCTAssertEqual(summary.skipped, 3, "Skipped: the record that isn't an event, the timeless one, the text")
        XCTAssertEqual(summary.firstSkippedLine, 3)
        XCTAssertEqual(summary.unsupported, ["bogus": 1])
        XCTAssertEqual(summary.unsupportedOther, 0)
        XCTAssertEqual(try storedMachTimes(in: store), [0, 1, 2, 3])
    }

    /// Unsupported types are counted under their first 64 names in file order, each cut to 64 characters. A name seen
    /// before the cap is still counted under it, and every other name is counted together.
    func testUnsupportedTypesAreNamedUpToTheCap() throws {
        let exit = try fixtureObject("eslogger-exit.jsonl")
        let maxTypes = TraceImporter.Summary.maxUnsupportedTypes
        let long = String(repeating: "x", count: TraceImporter.Summary.maxTypeNameLength + 36)
        let names = (0..<maxTypes + 6).map { "type_\($0)" }
        /// The long name, then every short one, then one short name kept and one past the cap again.
        let order = [long] + names + [names[0], names[names.count - 1]]
        let lines = try [esloggerExitLine(0, of: exit)] + order.map { try unsupported($0, in: exit) }
        let url = try temporaryFile(containing: lines.joined(separator: "\n"), named: "trace.jsonl")
        let summary = try openTrace(url, in: CoreDataController(model: eventModel))

        var expected = [String(long.prefix(TraceImporter.Summary.maxTypeNameLength)): 1]
        for name in names.prefix(maxTypes - 1) { expected[name] = 1 }
        expected[names[0]] = 2
        XCTAssertEqual(summary.unsupported, expected)
        XCTAssertEqual(summary.unsupportedOther, names.count - (maxTypes - 1) + 1)
        XCTAssertEqual(summary.unsupportedCount, order.count)
        XCTAssertEqual(summary.saved, 1)
        XCTAssertEqual(summary.skipped, 0)
    }

    // MARK: Preflight

    /// A file is turned away before anything is cleared when it holds no event Mac Monitor can show: nothing,
    /// whitespace, JSON that isn't an event, text, or only events of types Mac Monitor doesn't have. So is a folder.
    func testPreflightTurnsAwayFilesWithoutAnEvent() throws {
        let exit = try fixtureObject("eslogger-exit.jsonl")
        let cases: [(text: String, failure: TraceImporter.Failure)] = [
            ("", .empty),
            (" \n\n\t \n", .empty),
            (#"{"process":{}}"# + "\n[1, 2]\n" + #"{"finished":1,"count":0}"#, .notATrace),
            ("not JSON at all\nnor this", .notATrace),
            (try unsupported("bogus", in: exit), .notATrace),
        ]
        for (text, failure) in cases {
            let url = try temporaryFile(containing: text, named: "trace.jsonl")
            XCTAssertEqual(thrown(TraceImporter.Failure.self) { try TraceImporter.preflight(url) }, failure, text)
        }
        let folder = try makeTemporaryDirectory()
        XCTAssertEqual(thrown(TraceImporter.Failure.self) { try TraceImporter.preflight(folder) }, .notAFile)
    }

    /// The first event must be among the first ``TraceImporter/preflightRecords`` records: one more record that isn't
    /// an event before it, and the file is turned away.
    func testPreflightLooksAtTheFirstThousandRecords() throws {
        let event = try esloggerExitLine(0, of: try fixtureObject("eslogger-exit.jsonl"))
        let notAnEvent = #"{"process":{}}"#
        for before in [TraceImporter.preflightRecords - 1, TraceImporter.preflightRecords] {
            let lines = Array(repeating: notAnEvent, count: before) + [event]
            let url = try temporaryFile(containing: lines.joined(separator: "\n"), named: "trace.jsonl")
            let failure = thrown(TraceImporter.Failure.self) { try TraceImporter.preflight(url) }
            XCTAssertEqual(failure, before < TraceImporter.preflightRecords ? nil : .notATrace, "\(before) before")
        }
    }

    /// The first event must end within the first ``TraceImporter/preflightBytes`` of the file: one byte later, and the
    /// file is turned away.
    func testPreflightLooksAtTheFirstFourMebibytes() throws {
        let event = try esloggerExitLine(0, of: try fixtureObject("eslogger-exit.jsonl"))
        /// `{"pad":"` and `"}`, then the newline before the event.
        let padding = TraceImporter.preflightBytes - event.utf8.count - 11
        for extra in [0, 1] {
            let pad = #"{"pad":""# + String(repeating: "x", count: padding + extra) + #""}"#
            let url = try temporaryFile(containing: pad + "\n" + event, named: "trace.jsonl")
            XCTAssertEqual(try url.resourceValues(forKeys: [.fileSizeKey]).fileSize,
                           TraceImporter.preflightBytes + extra)
            let failure = thrown(TraceImporter.Failure.self) { try TraceImporter.preflight(url) }
            XCTAssertEqual(failure, extra == 0 ? nil : .notATrace, "\(extra) bytes past the limit")
        }
    }

    // MARK: How reading ends

    /// Stopping keeps every event read up to the stop, in file order, and reports how far through the file it got: to
    /// the end of the last event kept.
    func testAStopKeepsTheEventsReadSoFar() throws {
        let url = try esloggerTrace(Self.longTrace)
        let store = CoreDataController(model: eventModel)
        var importer: TraceImporter?
        /// On the main thread, which set `importer` before it could run this.
        _ = onFirstSave(of: store) { DispatchQueue.main.sync { importer?.stop() } }
        let opened = expectation(description: "opened")
        var summary: TraceImporter.Summary?
        importer = store.openTrace(at: url) { summary = $0; opened.fulfill() }
        wait(for: [opened], timeout: 120)

        let result = try XCTUnwrap(summary)
        XCTAssertNil(result.error)
        let stoppedAt = try XCTUnwrap(result.stoppedAt, "The stop wasn't reported")
        XCTAssertTrue(stoppedAt > 0 && stoppedAt < 1, "Stopped at \(stoppedAt)")
        XCTAssertGreaterThanOrEqual(result.saved, TraceImporter.batchSize)
        XCTAssertLessThan(result.saved, Self.longTrace, "Reading carried on past the stop")
        XCTAssertEqual(try storedMachTimes(in: store), (0..<Int64(result.saved)).map { $0 },
                       "The store doesn't hold exactly the events reported saved, from the start of the file")
        /// Each line and the newline after it, up to the last event kept's closing brace.
        let file = try Data(contentsOf: url)
        let lengths = file.split(separator: UInt8(ascii: "\n")).prefix(result.saved).map(\.count)
        let readTo = lengths.reduce(0, +) + result.saved - 1
        XCTAssertEqual(stoppedAt, Double(readTo) / Double(file.count), "Events read before the stop weren't kept")
    }

    /// A Clear while a trace is read stops the read, and the batches still on their way when it ran are dropped rather
    /// than saved into the store it emptied, whether the batches are built by the pipeline or on the store's queue.
    /// The summary counts only the batch saved before the Clear, and the drop isn't a failure.
    func testAClearMidImportDropsItsLateBatches() throws {
        try eachPipeline { pipelined in
            let url = try esloggerTrace(Self.longTrace)
            let store = CoreDataController(model: eventModel)
            let cleared = expectation(forNotification: CoreDataController.eventsDidClear, object: store)
            /// The Clear that opens the trace, and the one that closes it.
            cleared.expectedFulfillmentCount = 2
            let announced = onFirstSave(of: store) { DispatchQueue.main.sync { _ = store.clearSystemEvents() } }
            let summary = try openTrace(url, in: store, timeout: 120)
            wait(for: [cleared], timeout: 120)

            XCTAssertNil(summary.error, "pipelined: \(pipelined)")
            XCTAssertNotNil(summary.stoppedAt, "The Clear didn't stop the read (pipelined: \(pipelined))")
            XCTAssertEqual(announced(), 1, "A batch was saved after the Clear (pipelined: \(pipelined))")
            XCTAssertEqual(store.lastInsertBatch, 1, "pipelined: \(pipelined)")
            XCTAssertEqual(store.eventCount, 0, "The closed trace refilled the store (pipelined: \(pipelined))")
            XCTAssertEqual(summary.saved, TraceImporter.batchSize,
                           "Dropped batches were counted as saved (pipelined: \(pipelined))")
            XCTAssertNotNil(summary.timeRange, "pipelined: \(pipelined)")
        }
    }

    /// A save that fails ends the import as ``TraceImporter/Failure/storeFull``: reading stops, and the summary counts
    /// exactly the events the store holds. The store refusing saves (as it does once Mac Monitor is quitting) stands
    /// in for a full disk.
    func testAFailedSaveEndsTheImport() throws {
        try eachPipeline { pipelined in
            let url = try esloggerTrace(Self.longTrace)
            let store = CoreDataController(model: eventModel)
            _ = onFirstSave(of: store) { store.canSave.withLock { $0 = false } }
            var last: TraceImporter.Progress?
            let summary = try openTrace(url, in: store, timeout: 120) { last = $0 }

            XCTAssertEqual(summary.error as? TraceImporter.Failure, .storeFull, "pipelined: \(pipelined)")
            XCTAssertNil(summary.stoppedAt, "pipelined: \(pipelined)")
            XCTAssertEqual(summary.saved, TraceImporter.batchSize, "pipelined: \(pipelined)")
            XCTAssertEqual(try storedMachTimes(in: store), (0..<Int64(TraceImporter.batchSize)).map { $0 },
                           "pipelined: \(pipelined)")
            let progress = try XCTUnwrap(last, "No progress was reported")
            XCTAssertLessThan(progress.bytesRead, progress.totalBytes, "Reading went on after the failed save")
        }
    }
}
