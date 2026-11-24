//
//  StreamSlotsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Stream slots
/// Pins the cap on `macmonitor` streams: never more than the capacity, however the reserves and releases interleave,
/// and a stream reserving or releasing twice takes or frees one slot.
final class StreamSlotsTests: XCTestCase {
    /// Three streams fit, the fourth doesn't, and a release makes room.
    func testTheCapacityHolds() {
        let slots = StreamSlots(capacity: 3)
        XCTAssertTrue(slots.reserve(1))
        XCTAssertTrue(slots.reserve(2))
        XCTAssertTrue(slots.reserve(3))
        XCTAssertFalse(slots.reserve(4))
        slots.release(2)
        XCTAssertTrue(slots.reserve(4))
        XCTAssertEqual(slots.count, 3)
    }

    /// A second reserve by a stream holding a slot keeps its one slot. A second release frees nothing more.
    func testReservingAndReleasingAreIdempotent() {
        let slots = StreamSlots(capacity: 2)
        XCTAssertTrue(slots.reserve(1))
        XCTAssertTrue(slots.reserve(1))
        XCTAssertEqual(slots.count, 1)
        XCTAssertTrue(slots.reserve(2))
        slots.release(1)
        slots.release(1)
        slots.release(9)
        XCTAssertEqual(slots.count, 1)
        XCTAssertTrue(slots.reserve(3))
        XCTAssertFalse(slots.reserve(4))
    }

    /// Streams that all reserve at once, each holding its slot until every one has tried, get exactly the capacity.
    /// Once they release, the next round starts from no slots taken.
    func testConcurrentStreamsNeverExceedTheCapacity() {
        let (capacity, workers) = (3, 8)
        let slots = StreamSlots(capacity: capacity)
        for round in 0..<50 {
            let granted = reserveAtOnce((0..<workers).map { UInt64(round * 1_000 + $0) }, from: slots)
            XCTAssertEqual(granted.reserved, capacity, "Round \(round)")
            XCTAssertEqual(granted.held, capacity, "Round \(round)")
            XCTAssertEqual(slots.count, 0, "Round \(round)")
        }
    }
}


// MARK: - Contention
extension StreamSlotsTests {
    /// Reserve a slot for each stream on its own thread, all let go from one barrier, then release them together.
    ///
    /// Every thread waits at the barrier before any reserves, and no slot is released until every thread has tried,
    /// so each reserve contends with all the others.
    ///
    /// - Parameters:
    ///   - streams: The streams' session numbers, one thread each.
    ///   - slots: The slots they reserve.
    /// - Returns: How many reserves succeeded, and how many slots were taken once all had tried.
    private func reserveAtOnce(_ streams: [UInt64], from slots: StreamSlots) -> (reserved: Int, held: Int) {
        let (ready, tried, done) = (DispatchGroup(), DispatchGroup(), DispatchGroup())
        /// Gates every thread waits at, each opened once for all of them.
        let (barrier, release) = (DispatchGroup(), DispatchGroup())
        barrier.enter()
        release.enter()
        let reserved = OSAllocatedUnfairLock(initialState: 0)
        for stream in streams {
            [ready, tried, done].forEach { $0.enter() }
            Thread.detachNewThread {
                ready.leave()
                barrier.wait()
                let took = slots.reserve(stream)
                if took { reserved.withLock { $0 += 1 } }
                tried.leave()
                release.wait()
                if took { slots.release(stream) }
                done.leave()
            }
        }
        XCTAssertEqual(ready.wait(timeout: .now() + 5), .success, "Every thread reached the barrier")
        barrier.leave()
        XCTAssertEqual(tried.wait(timeout: .now() + 5), .success, "Every thread reserved")
        let held = slots.count
        release.leave()
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success, "Every thread released")
        return (reserved.withLock { $0 }, held)
    }
}
