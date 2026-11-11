//
//  CoreDataInsertPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Inserting a recording
/// Times Mac Monitor's side of a recording: `insertSystemEvents(messages:)`, which inserts each batch the Security
/// Extension sends, sharing process and file rows (``RowCache``), and saves it. Its replies are the back-pressure the
/// Security Extension waits on, so a slower insert holds events in its memory and then its spool.
final class CoreDataInsertPerformanceTests: PerformanceTestCase {
    /// Events per sample, in batches of the Security Extension's size (`EventBatcher.Limits.batchSize`).
    private static let (events, batchSize) = (5_000, 500)
    
    /// A recording's batches inserted into a new, empty store, as when recording starts.
    func testInsertSystemEvents() throws {
        let events = try recordingEvents(Self.events)
        let batches = stride(from: 0, to: events.count, by: Self.batchSize).map {
            Array(events[$0..<min($0 + Self.batchSize, events.count)])
        }
        try benchmark("store.insert", operations: events.count, setUp: { CoreDataController(model: eventModel) }) {
            store in
            let saved = DispatchGroup()
            for batch in batches {
                saved.enter()
                store.insertSystemEvents(messages: batch) { saved.leave() }
            }
            guard saved.wait(timeout: .now() + 300) == .success else { throw BenchmarkFailure("Inserts didn't end") }
            guard store.lastInsertBatch == Int64(batches.count) else { throw BenchmarkFailure("A batch wasn't saved") }
        }
    }
}
