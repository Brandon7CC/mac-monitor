//
//  TraceImportPipelineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/26/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Pipelined import
/// Pins the pipelined import (``TraceInsertPipeline``) to the import it replaced. The same trace opened both ways
/// leaves the same store, row for row. The shared rows, insert orders, batches, columns and export all match. A batch
/// the pipeline built for a trace that a Clear has since closed is dropped.
final class TraceImportPipelineTests: XCTestCase {
    /// A trace of every synthetic event, with the eslogger lineage fixture every 1,000 events. There are about three
    /// events a process. Processes come back after thousands of others, so shared rows cross batches, contexts and
    /// cache generations.
    ///
    /// - Parameter count: The synthetic events.
    /// - Returns: The trace's file, and how many events it holds: every line is one.
    private func trace(_ count: Int) throws -> (url: URL, events: Int) {
        let corpus = try SyntheticCorpus.records().map(\.message)
        let lineage = String(decoding: try fixture("eslogger-lineage.jsonl"), as: UTF8.self)
            .split(separator: "\n").map(String.init)
        var lines: [String] = []
        lines.reserveCapacity(count + (count / 1_000 + 1) * lineage.count)
        for index in 0..<count {
            var message = corpus[index % corpus.count]
            message.mach_time = Int64(index)
            let group = Int32(index / 3 % 3_000 + 100)
            message.process.pid = group
            if var token = message.process.audit_token {
                (token.pid, token.pidversion) = (group, group)
                message.process.audit_token = token
                message.process.audit_token_string = token.toString()
            }
            lines.append(exportText(message))
            if index % 1_000 == 0 { lines += lineage }
        }
        return (try temporaryFile(containing: lines.joined(separator: "\n"), named: "trace.jsonl"), lines.count)
    }

    /// Open a trace, and wait until it's read.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - pipelined: Build batches outside the store's queue.
    /// - Returns: The store, and what was read.
    private func open(_ url: URL, pipelined: Bool) throws -> (CoreDataController, TraceImporter.Summary) {
        let previous = TraceImporter.pipelined
        TraceImporter.pipelined = pipelined
        defer { TraceImporter.pipelined = previous }
        let store = CoreDataController(model: eventModel)
        return (store, try openTrace(url, in: store))
    }

    /// What a store holds. That's each entity's row count, and each event's attributes in insert order without its
    /// random IDs. It's also the export with every UUID blanked, since eslogger's events get new ones each read.
    ///
    /// - Parameter store: The store.
    /// - Returns: The rows, events and export.
    private func contents(of store: CoreDataController) throws
        -> (rows: [String: Int], events: [NSDictionary], export: String) {
        let context = store.container.newBackgroundContext()
        return try context.performAndWait {
            var rows: [String: Int] = [:]
            for entity in store.container.managedObjectModel.entities where !entity.isAbstract {
                let request = NSFetchRequest<NSFetchRequestResult>(entityName: entity.name!)
                request.includesSubentities = false
                rows[entity.name!] = try context.count(for: request)
            }
            let request = ESMessage.request(sortedBy: [NSSortDescriptor(key: "insert_order", ascending: true)])
            let keys = ESMessage.entity().attributesByName
                .filter { $0.value.attributeType != .UUIDAttributeType }.map(\.key)
            /// JSON kept as data (the action's result) is compared parsed. `JSONEncoder` writes keys in any order.
            let events = try context.fetch(request).map { event in
                event.dictionaryWithValues(forKeys: keys).mapValues { value -> Any in
                    (value as? Data).flatMap { try? JSONSerialization.jsonObject(with: $0) } ?? value
                } as NSDictionary
            }
            let hex = "[0-9A-Fa-f]"
            let uuid = try NSRegularExpression(pattern: "\(hex){8}-\(hex){4}-\(hex){4}-\(hex){4}-\(hex){12}")
            let text = try expectedExport(of: store.container)
            let export = uuid.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text),
                                                       withTemplate: "-")
            return (rows, events, export)
        }
    }

    /// A trace opened pipelined leaves the store the import before it left. Both read every line as an event: the
    /// 12,345 synthetic events and the lineage fixture's events each of the 13 times they're written.
    func testPipelinedImportStoresWhatTheImportBeforeStored() throws {
        let (url, events) = try trace(12_345)
        let (before, beforeSummary) = try open(url, pipelined: false)
        let (after, afterSummary) = try open(url, pipelined: true)
        for (summary, store) in [(beforeSummary, before), (afterSummary, after)] {
            XCTAssertNil(summary.error)
            XCTAssertEqual(summary.skipped, 0)
            XCTAssertEqual(summary.saved, events)
            XCTAssertEqual(store.eventCount, events)
        }
        XCTAssertEqual(afterSummary.timeRange, beforeSummary.timeRange)
        XCTAssertEqual(after.lastInsertBatch, before.lastInsertBatch)
        let (expected, actual) = (try contents(of: before), try contents(of: after))
        XCTAssertEqual(actual.rows, expected.rows)
        XCTAssertEqual(actual.events.count, expected.events.count)
        let different = zip(expected.events, actual.events).enumerated()
            .filter { !$1.0.isEqual(to: $1.1 as! [AnyHashable: Any]) }
        XCTAssertEqual(different.count, 0, "First different event: \(different.first.map { "\($0.element)" } ?? "")")
        XCTAssertTrue(actual.export == expected.export, "The exports differ")
    }

    /// Clear, and wait until the Clear has finished.
    ///
    /// - Parameters:
    ///   - store: The event store.
    ///   - source: What the store holds after it.
    /// - Returns: The Clear's number.
    private func clear(_ store: CoreDataController, to source: CoreDataController.EventSource) -> Int {
        let cleared = expectation(forNotification: CoreDataController.eventsDidClear, object: store)
        let clear = store.clearSystemEvents(source: source)
        wait(for: [cleared], timeout: 60)
        return clear
    }

    /// Build a batch of a trace's events in the pipeline, then save it, with or without a Clear in between, as a batch
    /// still on its way when a Clear closes its trace is.
    ///
    /// - Parameter clearing: Clear between the build and the save.
    /// - Returns: The store, and what the save reported.
    private func saveBatch(clearing: Bool) throws
        -> (store: CoreDataController, outcome: CoreDataController.TraceSave?) {
        let exit = try fixtureObject("eslogger-exit.jsonl")
        let messages = try (0..<20).map { index in
            try TraceImporter.message(from: Data(try esloggerExitLine(index, of: exit).utf8))
        }
        let store = CoreDataController(model: eventModel)
        let opening = clear(store, to: .trace(URL(fileURLWithPath: "/tmp/trace.jsonl")))
        guard case .built(let batch) = TraceInsertPipeline(store: store, clear: opening).build(messages) else {
            XCTFail("The batch wasn't built")
            return (store, nil)
        }
        if clearing { _ = clear(store, to: .live) }
        let done = expectation(description: "saved")
        var outcome: CoreDataController.TraceSave?
        store.saveTraceEvents(batch, clear: opening) { outcome = $0; done.fulfill() }
        wait(for: [done], timeout: 60)
        return (store, outcome)
    }

    /// A batch built before a Clear closed its trace, and saved after, is dropped: the store the Clear emptied stays
    /// empty, no batch is announced, and the save reports the batch dropped rather than saved or failed. Built and
    /// saved with no Clear in between, the same batch is stored.
    func testABatchBuiltBeforeAClearIsDroppedAfterIt() throws {
        let kept = try saveBatch(clearing: false)
        XCTAssertEqual(kept.outcome, .saved)
        XCTAssertEqual(try storedMachTimes(in: kept.store), Array(0..<20))
        XCTAssertEqual(kept.store.lastInsertBatch, 1)

        let dropped = try saveBatch(clearing: true)
        XCTAssertEqual(dropped.outcome, .dropped, "A closed trace's batch wasn't reported dropped")
        XCTAssertEqual(dropped.store.eventCount, 0, "A batch of the closed trace was saved")
        XCTAssertEqual(dropped.store.lastInsertBatch, 0)
    }
}
