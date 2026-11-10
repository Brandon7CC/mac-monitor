//
//  EventHandoffTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Handing events to a queue
/// Pins ``EventHandoff``: every event reaches the queue, in the order it was submitted, a run of them with one wake
/// of the queue, a flush delivers what's pending at once, as a stream's stop relies on, and a run waits its delay.
final class EventHandoffTests: XCTestCase {
    /// The queue events are delivered on.
    private let queue = DispatchQueue(label: "EventHandoffTests")

    /// - Parameter number: An event's number.
    /// - Returns: A stand-in for the event's JSON.
    private func event(_ number: Int) -> Data {
        Data("\(number)".utf8)
    }

    /// Events submitted while the queue is busy are delivered together, in order, with one wake.
    func testARunIsDeliveredTogetherInOrder() {
        var runs: [[Data]] = []
        let handoff = EventHandoff(queue: queue, delay: .nanoseconds(0)) { runs.append($0) }
        queue.sync { for number in 0..<1_000 { handoff.submit(event(number)) } }
        queue.sync {}
        XCTAssertEqual(runs.count, 1, "One wake for the run")
        XCTAssertEqual(runs.first, (0..<1_000).map(event))
    }

    /// An event submitted after a run was taken wakes the queue again.
    func testTheNextEventWakesTheQueueAgain() {
        var runs: [[Data]] = []
        let handoff = EventHandoff(queue: queue, delay: .nanoseconds(0)) { runs.append($0) }
        for number in 0..<3 {
            handoff.submit(event(number))
            queue.sync {}
        }
        XCTAssertEqual(runs, (0..<3).map { [event($0)] })
    }

    /// A flush on the queue delivers every event submitted so far, at once, however long the delay: a stream's stop
    /// follows every event. The delayed wake then finds nothing, and delivers nothing twice.
    func testAFlushDeliversWhatIsPending() {
        var runs: [[Data]] = []
        let handoff = EventHandoff(queue: queue, delay: .milliseconds(50)) { runs.append($0) }
        handoff.submit(event(0))
        handoff.submit(event(1))
        queue.sync { handoff.flush() }
        XCTAssertEqual(runs, [[event(0), event(1)]])
        queue.sync { handoff.flush() }
        XCTAssertEqual(runs.count, 1, "Nothing pending delivers nothing")
        XCTAssertTrue(waitUntil { self.queue.sync { runs.count } == 1 })
        usleep(120_000)
        XCTAssertEqual(queue.sync { runs.count }, 1, "The delayed wake found nothing")
    }

    /// Without a flush, a run is delivered once its delay has passed, together.
    func testARunWaitsItsDelay() {
        var runs: [[Data]] = []
        let handoff = EventHandoff(queue: queue, delay: .milliseconds(30)) { runs.append($0) }
        for number in 0..<100 { handoff.submit(event(number)) }
        XCTAssertEqual(queue.sync { runs.count }, 0, "Not before the delay")
        XCTAssertTrue(waitUntil { self.queue.sync { runs.count } == 1 })
        XCTAssertEqual(queue.sync { runs.first }, (0..<100).map(event))
    }

    /// Lanes submit at once: every event arrives exactly once, each lane's in the order it submitted them, and with
    /// far fewer wakes than events.
    func testLanesSubmittingAtOnceLoseNothing() {
        let lanes = 4, perLane = 5_000
        var received: [Data] = [], wakes = 0
        let handoff = EventHandoff(queue: queue, delay: .milliseconds(1)) { events in
            received += events
            wakes += 1
        }
        DispatchQueue.concurrentPerform(iterations: lanes) { lane in
            for number in 0..<perLane { handoff.submit(event(lane * perLane + number)) }
        }
        queue.sync { handoff.flush() }
        let numbers = received.compactMap { Int(String(decoding: $0, as: UTF8.self)) }
        XCTAssertEqual(numbers.count, lanes * perLane)
        XCTAssertEqual(Set(numbers).count, lanes * perLane, "Each exactly once")
        for lane in 0..<lanes {
            let own = numbers.filter { $0 / perLane == lane }
            XCTAssertEqual(own, own.sorted(), "Lane \(lane) in its own order")
        }
        XCTAssertLessThan(wakes, lanes * perLane)
    }
}
