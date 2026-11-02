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
/// leaves the same store, row for row. The shared rows, insert orders, batches, columns and export all match.
final class TraceImportPipelineTests: XCTestCase {
    /// A trace of every synthetic event, with the eslogger lineage fixture every 1,000 events. There are about three
    /// events a process. Processes come back after thousands of others, so shared rows cross batches, contexts and
    /// cache generations.
    ///
    /// - Parameter count: The synthetic events.
    /// - Returns: The trace's file.
    private func trace(_ count: Int) throws -> URL {
        let corpus = try SyntheticCorpus.records().map(\.message)
        let lineage = String(decoding: try fixture("eslogger-lineage.jsonl"), as: UTF8.self)
            .split(separator: "\n").map(String.init)
        var lines: [String] = []
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
        return try temporaryFile(containing: lines.joined(separator: "\n"), named: "trace.jsonl")
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
        let opened = expectation(description: "opened")
        var summary: TraceImporter.Summary?
        store.openTrace(at: url) { summary = $0; opened.fulfill() }
        wait(for: [opened], timeout: 300)
        return (store, try XCTUnwrap(summary))
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

    /// A trace opened pipelined leaves the store the import before it left.
    func testPipelinedImportStoresWhatTheImportBeforeStored() throws {
        let url = try trace(12_345)
        let (before, beforeSummary) = try open(url, pipelined: false)
        let (after, afterSummary) = try open(url, pipelined: true)
        XCTAssertNil(afterSummary.error)
        XCTAssertEqual(afterSummary.saved, beforeSummary.saved)
        XCTAssertGreaterThan(afterSummary.saved, 12_345)
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
}
