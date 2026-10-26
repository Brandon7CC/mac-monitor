//
//  CaptureSession+Drain.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Draining
extension CaptureSession {
    /// Stop new messages and wait until every message Endpoint Security already queued for the session's clients has
    /// been handled, so a stream that's stopping keeps everything captured up to that moment. Call it before
    /// ``stop()``, on the session's queue.
    ///
    /// 1. `es_unsubscribe_all` on each client: Endpoint Security queues no more messages for it.
    /// 2. `es_sync_client` on each client: its marker reaches the front of the client's queue once every message
    ///    before it has been handled, and so emitted.
    /// 3. Once every client's marker has, any held app execs go out with the answer they have, along with the events
    ///    waiting behind them. A lookup still running is ignored.
    /// 4. Then `completion` runs on `queue`. Every event emitted so far hopped onto `queue` first, so `completion`
    ///    runs after all of them.
    ///
    /// Before macOS 27 there's no `es_sync_client`: the clients only stop queueing messages, and those still queued
    /// are dropped by ``stop()``.
    ///
    /// - Parameters:
    ///   - queue: The session's queue, which the session's `emit` hops onto.
    ///   - completion: Called once on `queue`, right away if the session is stopped.
    public func drain(on queue: DispatchQueue, completion: @escaping () -> Void) {
        guard !isStopped else { return queue.async(execute: completion) }
        lanes.forEach { _ = $0.client?.unsubscribeAll() }
        let synced = DispatchGroup()
        for lane in lanes {
            synced.enter()
            if lane.client?.sync({ synced.leave() }) != true { synced.leave() }
        }
        synced.notify(queue: queue) { [lanes] in
            lanes.forEach { $0.releaseHeld() }
            queue.async(execute: completion)
        }
    }
}
