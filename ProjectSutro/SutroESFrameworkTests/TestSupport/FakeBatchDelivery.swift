//
//  FakeBatchDelivery.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Fake delivery
/// A reader a test controls: it keeps every batch an ``EventBatcher`` sends and replies only when the test says so.
final class FakeBatchDelivery: EventBatchDelivery {
    /// The batches sent, and the replies not yet given.
    private struct State {
        var batches: [[Data]] = []
        var pending: [(Bool) -> Void] = []
    }
    
    private let state = OSAllocatedUnfairLock(uncheckedState: State())
    
    /// Every batch sent, in order.
    var batches: [[Data]] {
        state.withLockUnchecked { $0.batches }
    }
    
    /// Every event sent, in order, as the text ``EventBatcherTests`` encodes them with.
    var events: [String] {
        batches.flatMap { $0.map { String(decoding: $0, as: UTF8.self) } }
    }
    
    /// Batches awaiting a reply.
    var pendingCount: Int {
        state.withLockUnchecked { $0.pending.count }
    }
    
    /// Keep the batch and its completion.
    ///
    /// - Parameters:
    ///   - batch: The events.
    ///   - completion: Called by ``reply(_:)``.
    func deliver(_ batch: [Data], completion: @escaping (Bool) -> Void) {
        state.withLockUnchecked { state in
            state.batches.append(batch)
            state.pending.append(completion)
        }
    }
    
    /// Reply to the oldest batch awaiting a reply.
    ///
    /// - Parameter delivered: `true` for a reply, `false` for a lost batch.
    func reply(_ delivered: Bool = true) {
        let completion = state.withLockUnchecked { $0.pending.isEmpty ? nil : $0.pending.removeFirst() }
        completion?(delivered)
    }
}


// MARK: - Fake backlog
/// An in-memory backlog that can refuse writes or fail reads.
final class FakeBacklog: EventBacklog {
    /// Events written but not read.
    private var events: [Data] = []
    /// Refuse every write.
    var refusesWrites = false
    /// Fail every read.
    var failsReads = false
    
    /// The events written but not yet read.
    var count: Int { events.count }
    
    /// Keep an event, unless writes are refused.
    ///
    /// - Parameter event: The event.
    /// - Throws: `CocoaError(.fileWriteOutOfSpace)` while ``refusesWrites`` is set.
    func append(_ event: Data) throws {
        guard !refusesWrites else { throw CocoaError(.fileWriteOutOfSpace) }
        events.append(event)
    }
    
    /// The oldest events, unless reads fail.
    ///
    /// - Parameter limit: The most events to return.
    /// - Returns: The oldest events.
    /// - Throws: `CocoaError(.fileReadCorruptFile)` while ``failsReads`` is set.
    func read(upTo limit: Int) throws -> [Data] {
        guard !failsReads else { throw CocoaError(.fileReadCorruptFile) }
        let read = Array(events.prefix(limit))
        events.removeFirst(read.count)
        return read
    }
}
