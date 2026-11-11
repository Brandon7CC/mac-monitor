//
//  StopWatchdog.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Stop watchdog
/// Exits `macmonitor` when a command a signal asked to stop hasn't stopped by a deadline, with 128 plus the signal's
/// number, as a shell reports a command a signal ended. A stream's stop waits for the Security Extension's answer,
/// which a stalled standard output can hold up.
public struct StopWatchdog: Sendable {
    /// How long a stop may take.
    public let deadline: DispatchTimeInterval
    /// Exits with a status.
    private let exit: @Sendable (Int32) -> Void

    /// - Parameters:
    ///   - deadline: How long a stop may take: 3 seconds, unless a test brings its own.
    ///   - exit: Exits with a status: `_exit`, unless a test records it instead.
    public init(deadline: DispatchTimeInterval = .seconds(3),
                exit: @escaping @Sendable (Int32) -> Void = { status in _exit(status) }) {
        self.deadline = deadline
        self.exit = exit
    }

    /// Exit at the deadline, from a global queue, so a busy or blocked main queue can't hold it up.
    ///
    /// - Parameter signal: The signal that started the stop, such as `SIGINT`: the exit status is 128 plus it.
    public func arm(for signal: Int32) {
        DispatchQueue.global().asyncAfter(deadline: .now() + deadline) { [exit] in exit(128 + signal) }
    }
}
