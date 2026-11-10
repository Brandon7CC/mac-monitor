//
//  XCTestCase+Trace.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import CoreData
@testable import SutroESFramework


// MARK: - Traces to open
extension XCTestCase {
    /// eslogger's exit event (the `eslogger-exit.jsonl` fixture) as one line of a trace, numbered: its `mach_time` and
    /// `global_seq_num` are `index`, so an event read back says which line it came from.
    ///
    /// - Parameters:
    ///   - index: The event's number.
    ///   - record: The exit fixture's object, read once by the caller.
    /// - Returns: The line, without its newline.
    /// - Throws: The error serializing the record.
    func esloggerExitLine(_ index: Int, of record: [String: Any]) throws -> String {
        var record = record
        record["mach_time"] = index
        record["global_seq_num"] = index
        return String(decoding: try JSONSerialization.data(withJSONObject: record), as: UTF8.self)
    }

    /// A JSONL trace of numbered exit events (``esloggerExitLine(_:of:)``), from 0, in a temporary folder.
    ///
    /// - Parameter count: The events.
    /// - Returns: The trace's file.
    /// - Throws: The error reading the fixture or writing the file.
    func esloggerTrace(_ count: Int) throws -> URL {
        let exit = try fixtureObject("eslogger-exit.jsonl")
        let lines = try (0..<count).map { try esloggerExitLine($0, of: exit) }
        return try temporaryFile(containing: lines.joined(separator: "\n"), named: "trace.jsonl")
    }

    /// Open a trace in a store, and wait until it's read.
    ///
    /// - Parameters:
    ///   - url: The trace.
    ///   - store: The event store.
    ///   - timeout: How long reading may take.
    ///   - progress: Called on the main thread with each report the import makes.
    /// - Returns: What the import read.
    /// - Throws: An `XCTest` failure if it didn't finish in time.
    func openTrace(_ url: URL, in store: CoreDataController, timeout: TimeInterval = 300,
                   progress: @escaping (TraceImporter.Progress) -> Void = { _ in }) throws -> TraceImporter.Summary {
        let opened = expectation(description: "opened")
        var summary: TraceImporter.Summary?
        store.openTrace(at: url, progress: progress) { summary = $0; opened.fulfill() }
        wait(for: [opened], timeout: timeout)
        return try XCTUnwrap(summary)
    }

    /// The `mach_time` of every event in a store, in the order they reached it.
    ///
    /// - Parameter store: The event store.
    /// - Returns: Each event's `mach_time`: a numbered trace's line numbers (``esloggerExitLine(_:of:)``).
    /// - Throws: The error fetching the events.
    func storedMachTimes(in store: CoreDataController) throws -> [Int64] {
        let context = store.container.newBackgroundContext()
        return try context.performAndWait {
            let request = ESMessage.request(sortedBy: [NSSortDescriptor(key: "insert_order", ascending: true)])
            return try context.fetch(request).map(\.mach_time)
        }
    }
}
