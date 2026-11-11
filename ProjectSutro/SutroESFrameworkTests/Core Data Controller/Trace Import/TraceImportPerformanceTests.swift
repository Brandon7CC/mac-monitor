//
//  TraceImportPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Opening a trace
/// Times File > Open Trace...: ``TraceImporter`` reading a JSONL trace, decoding each record, and saving it through
/// the pipelined insert (``TraceInsertPipeline``), into a new store.
final class TraceImportPerformanceTests: PerformanceTestCase {
    /// Events in the trace.
    private static let events = 10_000
    
    /// A recording's trace, from the first line to the last batch saved.
    func testOpenTrace() throws {
        let url = try recordingTrace(Self.events)
        try benchmark("import.trace", operations: Self.events, setUp: { CoreDataController(model: eventModel) }) {
            store in
            let opened = expectation(description: "opened")
            var summary: TraceImporter.Summary?
            store.openTrace(at: url) { summary = $0; opened.fulfill() }
            guard XCTWaiter().wait(for: [opened], timeout: 300) == .completed, let summary else {
                throw BenchmarkFailure("The trace wasn't read")
            }
            guard summary.error == nil, summary.saved == Self.events else {
                let reason = summary.error.map { "\($0)" } ?? "no error"
                throw BenchmarkFailure("Saved \(summary.saved) of \(Self.events) events: \(reason)")
            }
        }
    }
}
