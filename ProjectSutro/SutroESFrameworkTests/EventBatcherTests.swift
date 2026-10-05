//
//  EventBatcherTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Event batcher
/// Pins how events reach a reader: full batches right away and partial ones after the flush delay, never more batches
/// in flight than the window, in order through the backlog (Mac Monitor), and paused rather than buffered without
/// bound (`macmonitor`).
final class EventBatcherTests: XCTestCase {
    private let queue = DispatchQueue(label: "EventBatcherTests")
    private let delivery = FakeBatchDelivery()
    
    /// A batcher on the test's queue and fake reader.
    ///
    /// - Parameters:
    ///   - limits: Batch size and pacing.
    ///   - overflow: The overflow policy.
    ///   - willSend: Called before each batch.
    /// - Returns: The batcher.
    private func makeBatcher(_ limits: EventBatcher.Limits, overflow: EventOverflow,
                             willSend: @escaping () -> Void = {}) -> EventBatcher {
        EventBatcher(queue: queue, limits: limits, overflow: overflow, delivery: delivery, willSend: willSend,
                     label: "Test")
    }
    
    /// Limits for a test. The flush delay defaults to a minute, so only full batches go out on their own.
    ///
    /// - Parameters:
    ///   - batchSize: The most events in a batch.
    ///   - window: The most batches in flight.
    ///   - memory: The most events in memory.
    ///   - delay: The flush delay.
    /// - Returns: The limits.
    private func limits(batch batchSize: Int, window: Int, memory: Int,
                        delay: DispatchTimeInterval = .seconds(60)) -> EventBatcher.Limits {
        EventBatcher.Limits(batchSize: batchSize, flushDelay: delay, maxBatchesInFlight: window, memoryLimit: memory)
    }
    
    /// Enqueue events named by numbers, on the batcher's queue.
    ///
    /// - Parameters:
    ///   - numbers: The events.
    ///   - batcher: The batcher.
    private func enqueue(_ numbers: ClosedRange<Int>, to batcher: EventBatcher) {
        queue.sync { numbers.forEach { batcher.enqueue(Data("\($0)".utf8)) } }
    }
    
    /// Reply to the oldest batch, then let the batcher handle the reply.
    ///
    /// - Parameter delivered: `true` for a reply, `false` for a lost batch.
    private func reply(_ delivered: Bool = true) {
        delivery.reply(delivered)
        queue.sync {}
    }
    
    /// A batch goes out as soon as it's full, and a partial one after the flush delay.
    func testFullBatchesGoRightAwayAndPartialOnesAfterTheDelay() {
        let batcher = makeBatcher(limits(batch: 3, window: 4, memory: 100, delay: .milliseconds(20)),
                                  overflow: .pause { _ in })
        enqueue(1...3, to: batcher)
        XCTAssertEqual(delivery.events, ["1", "2", "3"])
        enqueue(4...5, to: batcher)
        XCTAssertEqual(delivery.batches.count, 1)
        XCTAssertTrue(waitUntil { self.delivery.batches.count == 2 })
        XCTAssertEqual(delivery.events, ["1", "2", "3", "4", "5"])
    }
    
    /// No more batches await a reply than the window allows; each reply sends the next, in order.
    func testTheWindowLimitsBatchesInFlight() {
        let batcher = makeBatcher(limits(batch: 1, window: 2, memory: 100), overflow: .pause { _ in })
        enqueue(1...5, to: batcher)
        XCTAssertEqual(delivery.events, ["1", "2"])
        reply()
        XCTAssertEqual(delivery.events, ["1", "2", "3"])
        (1...4).forEach { _ in reply() }
        XCTAssertEqual(delivery.events, ["1", "2", "3", "4", "5"])
        XCTAssertEqual(queue.sync { batcher.counters.delivered }, 5)
    }
    
    /// Past the memory limit events spill to the backlog, and every event still reaches the reader in order. The
    /// backlog is released once it's drained.
    func testTheBacklogIsLosslessAndInOrder() {
        weak var made: FakeBacklog?
        let batcher = makeBatcher(limits(batch: 2, window: 1, memory: 4), overflow: .backlog {
            let backlog = FakeBacklog()
            made = backlog
            return backlog
        })
        enqueue(1...20, to: batcher)
        XCTAssertNotNil(made)
        while delivery.pendingCount > 0 { reply() }
        XCTAssertEqual(delivery.events, (1...20).map(String.init))
        XCTAssertNil(made, "The backlog is released once it's drained.")
        let counters = queue.sync { batcher.counters }
        XCTAssertEqual(counters.spooled, 14)
        XCTAssertEqual(counters.delivered, 20)
        XCTAssertEqual(counters.dropped, 0)
    }
    
    /// A backlog that refuses events, or can't be read, loses those events and counts them.
    func testABrokenBacklogCountsWhatItLoses() {
        let backlog = FakeBacklog()
        let batcher = makeBatcher(limits(batch: 2, window: 1, memory: 2), overflow: .backlog { backlog })
        /// 1 and 2 are sent, 3 and 4 wait in memory, 5 and 6 go to the backlog.
        enqueue(1...6, to: batcher)
        backlog.refusesWrites = true
        enqueue(7...8, to: batcher)
        backlog.failsReads = true
        reply()
        reply()
        XCTAssertEqual(delivery.events, ["1", "2", "3", "4"])
        XCTAssertEqual(queue.sync { batcher.counters.dropped }, 4, "2 refused and 2 lost with the unreadable backlog")
    }
    
    /// With the pause policy, a full buffer drops events and pauses the source once, and the source resumes once the
    /// buffer has drained to half. No backlog is ever made.
    func testThePausePolicyPausesOnceAndResumesAtHalf() {
        var calls: [Bool] = []
        let batcher = makeBatcher(limits(batch: 2, window: 1, memory: 4), overflow: .pause { calls.append($0) })
        enqueue(1...8, to: batcher)
        XCTAssertEqual(calls, [true])
        XCTAssertTrue(queue.sync { batcher.isPaused })
        reply()
        XCTAssertEqual(calls, [true], "4 events are still buffered, more than half the limit.")
        reply()
        XCTAssertEqual(calls, [true, false])
        while delivery.pendingCount > 0 { reply() }
        XCTAssertEqual(delivery.events, ["1", "2", "3", "4", "5", "6"])
        let counters = queue.sync { batcher.counters }
        XCTAssertEqual(counters.dropped, 2)
        XCTAssertEqual(counters.pauses, 1)
        XCTAssertEqual(counters.spooled, 0)
    }
    
    /// Each batch is announced just before it goes out.
    func testWillSendRunsBeforeEachBatch() {
        var announced = 0
        let batcher = makeBatcher(limits(batch: 1, window: 4, memory: 100), overflow: .pause { _ in },
                                  willSend: { announced += 1 })
        enqueue(1...3, to: batcher)
        XCTAssertEqual(announced, 3)
    }
    
    /// A lost batch frees its slot but isn't counted as delivered.
    func testALostBatchFreesItsSlot() {
        let batcher = makeBatcher(limits(batch: 1, window: 1, memory: 100), overflow: .pause { _ in })
        enqueue(1...1, to: batcher)
        reply(false)
        enqueue(2...2, to: batcher)
        XCTAssertEqual(delivery.events, ["1", "2"])
        XCTAssertEqual(queue.sync { batcher.counters.delivered }, 0)
    }
    
    /// Once closed, nothing more is sent, late replies are ignored, and a pending flush does nothing.
    func testCloseStopsEverything() {
        let batcher = makeBatcher(limits(batch: 2, window: 1, memory: 100, delay: .milliseconds(10)),
                                  overflow: .pause { _ in })
        enqueue(1...3, to: batcher)
        queue.sync { batcher.close() }
        reply()
        enqueue(4...6, to: batcher)
        usleep(50_000)
        queue.sync {}
        XCTAssertEqual(delivery.events, ["1", "2"])
        let counters = queue.sync { batcher.counters }
        XCTAssertEqual(counters.delivered, 0)
        XCTAssertEqual(counters.enqueued, 3)
    }
    
    /// A drain sends what's buffered without waiting for the flush delay and completes once the reader has replied to
    /// everything.
    func testDrainCompletesOnceEverythingIsDelivered() {
        let batcher = makeBatcher(limits(batch: 2, window: 1, memory: 100), overflow: .pause { _ in })
        enqueue(1...3, to: batcher)
        var drained = 0
        queue.sync { batcher.drain { drained += 1 } }
        XCTAssertEqual(delivery.events, ["1", "2"])
        reply()
        XCTAssertEqual(delivery.events, ["1", "2", "3"])
        XCTAssertEqual(drained, 0)
        reply()
        XCTAssertEqual(drained, 1)
    }
    
    /// A drain completes right away when nothing is waiting, and when the batcher closes.
    func testDrainCompletesWhenIdleOrClosed() {
        let batcher = makeBatcher(limits(batch: 2, window: 1, memory: 100), overflow: .pause { _ in })
        var drained = 0
        queue.sync { batcher.drain { drained += 1 } }
        XCTAssertEqual(drained, 1)
        enqueue(1...2, to: batcher)
        queue.sync { batcher.drain { drained += 1 } }
        XCTAssertEqual(drained, 1)
        queue.sync { batcher.close() }
        XCTAssertEqual(drained, 2)
        queue.sync { batcher.drain { drained += 1 } }
        XCTAssertEqual(drained, 3)
    }
}
