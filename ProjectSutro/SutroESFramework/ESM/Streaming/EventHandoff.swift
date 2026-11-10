//
//  EventHandoff.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation
import os


// MARK: - Handing events to a queue
/// Hands a capture session's events from its lanes to the serial queue that batches them, waking that queue once for
/// every run of events rather than once for each.
///
/// A lane calls ``submit(_:)`` from Endpoint Security's handler, under its own locks, for every event it emits. A
/// block on the queue for each one costs an allocation and a wake of the queue's thread per event, which under load
/// was a tenth to a quarter of a lane's time. Here an event is appended under a lock held for a few instructions, and
/// only the first one of a run schedules the queue, ``delay`` later: its block takes every event that arrived
/// meanwhile. The delay is what makes a run: a queue woken at once is done before the next event comes, even at
/// thousands a second, and would be woken for each. The events' batcher holds a partial batch twenty times longer.
///
/// Order is kept: events are delivered in the order they were submitted, a lane's own in the order it emitted them.
/// Whoever needs every event submitted so far, as a stream does before it answers a stop, calls ``flush()`` on the
/// queue.
///
/// **Threading:** ``submit(_:)`` is safe from any thread. `deliver` and ``flush()`` run on the queue.
final class EventHandoff: @unchecked Sendable {
    /// What the lock guards.
    private struct State {
        /// Events submitted and not yet taken, oldest first.
        var pending: [Data] = []
        /// Is a block on the queue to take them?
        var isScheduled = false
    }

    /// The most room kept for the next run, so one burst doesn't hold its memory for good.
    private static let keptCapacity = 512
    private let state = OSAllocatedUnfairLock(uncheckedState: State())
    private let queue: DispatchQueue
    private let deliver: ([Data]) -> Void
    /// How long a run's first event waits before the queue takes the run: 5 ms unless a test says otherwise.
    let delay: DispatchTimeInterval

    /// - Parameters:
    ///   - queue: The serial queue the events are delivered on.
    ///   - delay: How long a run's first event waits before the queue takes the run.
    ///   - deliver: Takes a run of events, oldest first, on `queue`.
    init(queue: DispatchQueue, delay: DispatchTimeInterval = .milliseconds(5),
         deliver: @escaping ([Data]) -> Void) {
        self.queue = queue
        self.delay = delay
        self.deliver = deliver
    }

    /// Hand over one event. It never blocks: the lock is held only to append.
    ///
    /// - Parameter event: A serialized event.
    func submit(_ event: Data) {
        let schedules = state.withLockUnchecked { state -> Bool in
            state.pending.append(event)
            guard !state.isScheduled else { return false }
            state.isScheduled = true
            return true
        }
        guard schedules else { return }
        queue.asyncAfter(deadline: .now() + delay) { [self] in flush() }
    }

    /// Deliver every event submitted so far, now. Call on the queue.
    func flush() {
        let events = take()
        if !events.isEmpty { deliver(events) }
    }

    /// Take every event submitted so far, so the next one schedules the queue again.
    ///
    /// - Returns: The events, oldest first.
    private func take() -> [Data] {
        state.withLockUnchecked { state in
            state.isScheduled = false
            let events = state.pending
            state.pending = []
            state.pending.reserveCapacity(Swift.min(events.count, Self.keptCapacity))
            return events
        }
    }
}
