//
//  DeadlineQueue.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation
import os


// MARK: - Work with a deadline
/// Runs work that could block for good, such as Security reading files a local user controls, off the caller's
/// thread, and waits for it only until a deadline.
///
/// Work that misses its deadline keeps its thread until it returns, and until then every other run is refused at once:
/// a stuck read holds a thread of this queue's, never the capture lane that asked for it, and no more are taken.
final class DeadlineQueue {
    /// One run's result, and whether its caller stopped waiting for it. Guarded by ``stuckRuns``' lock.
    private final class Run<Value> {
        var value: Value?
        var isFinished = false
        var isAbandoned = false
    }

    /// The queue the work runs on.
    private let queue: DispatchQueue
    /// How long a caller waits.
    private let timeout: DispatchTimeInterval
    /// How many runs that missed their deadline are still running. Its lock guards every ``Run`` too.
    private let stuckRuns = OSAllocatedUnfairLock(initialState: 0)

    /// A queue whose callers wait up to a timeout.
    ///
    /// - Parameters:
    ///   - label: The dispatch queue's label.
    ///   - timeout: How long a caller waits for its work.
    init(label: String, timeout: DispatchTimeInterval) {
        queue = DispatchQueue(label: label, qos: .userInitiated, attributes: .concurrent)
        self.timeout = timeout
    }

    /// Is work that missed its deadline still running, so that runs are refused?
    var isStuck: Bool {
        stuckRuns.withLock { $0 > 0 }
    }

    /// Run work and wait for it until the deadline.
    ///
    /// - Parameter work: The work.
    /// - Returns: The work's result, or `nil` when it missed the deadline, or when earlier work that missed its own is
    ///   still running, and then the work isn't run.
    func run<Value>(_ work: @escaping () -> Value?) -> Value? {
        guard !isStuck else { return nil }
        let run = Run<Value>()
        let done = DispatchSemaphore(value: 0)
        queue.async { [stuckRuns] in
            let value = work()
            stuckRuns.withLockUnchecked { stuck in
                run.value = value
                run.isFinished = true
                if run.isAbandoned { stuck -= 1 }
            }
            done.signal()
        }
        _ = done.wait(timeout: .now() + timeout)
        return stuckRuns.withLockUnchecked { stuck in
            guard run.isFinished else {
                run.isAbandoned = true
                stuck += 1
                return nil
            }
            return run.value
        }
    }
}
