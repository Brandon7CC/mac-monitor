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
    
    /// A second reserve by a stream holding a slot keeps its one slot; a second release frees nothing more.
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
    
    /// Reserves and releases from many threads at once never hold more than the capacity.
    func testConcurrentStreamsNeverExceedTheCapacity() {
        let slots = StreamSlots(capacity: 3)
        let held = OSAllocatedUnfairLock(initialState: (now: 0, most: 0))
        DispatchQueue.concurrentPerform(iterations: 8) { worker in
            for round in 0..<500 {
                let stream = UInt64(worker * 1_000 + round)
                guard slots.reserve(stream) else { continue }
                held.withLock { held in
                    held.now += 1
                    held.most = max(held.most, held.now)
                }
                held.withLock { $0.now -= 1 }
                slots.release(stream)
            }
        }
        XCTAssertLessThanOrEqual(held.withLock { $0.most }, 3)
        XCTAssertEqual(slots.count, 0)
    }
}
