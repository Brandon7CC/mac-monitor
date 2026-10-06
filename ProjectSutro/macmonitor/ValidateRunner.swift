//
//  ValidateRunner.swift
//  macmonitor
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import os
import SutroESFramework


// MARK: - Validate runner
/// `macmonitor validate`, as a process: standard output, signals, and the exit status. The check itself is
/// ``ValidateCommand``'s.
///
/// **Stopping:** the check runs off the main queue, so a signal can reach it. The first `SIGINT`, `SIGTERM` or
/// `SIGHUP` stops it before its next record; the report so far is written, saying it stopped, and `macmonitor` exits
/// by that signal (130 for Ctrl-C), as a stream does. A second signal exits at once.
final class ValidateRunner {
    /// The one check this process runs.
    private static var current: ValidateRunner?
    /// The signal that stopped the check, if one did. The check reads it before each record.
    private let stoppingSignal = OSAllocatedUnfairLock<Int32?>(initialState: nil)
    private var trap: SignalTrap?
    
    /// Start checking. Runs until it exits, on the main queue.
    ///
    /// - Parameter invocation: The trace, and which of its keys to check.
    static func start(_ invocation: ValidateInvocation) {
        let runner = ValidateRunner()
        current = runner
        runner.trap = SignalTrap { [weak runner] number in runner?.received(number) }
        let stopping = runner.stoppingSignal
        let command = ValidateCommand(output: FileOutput(descriptor: STDOUT_FILENO),
                                      isCancelled: { stopping.withLock { $0 != nil } })
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = command.run(invocation)
            DispatchQueue.main.async { runner.finish(outcome) }
        }
    }
    
    /// Stop on the first signal; exit on the second.
    ///
    /// - Parameter number: The signal.
    private func received(_ number: Int32) {
        let first = stoppingSignal.withLock { stopping in
            defer { stopping = stopping ?? number }
            return stopping == nil
        }
        guard first else { _exit(128 + number) }
    }
    
    /// Exit the way the check ended: by the signal that stopped it, else 0 for a valid trace, 65 for an invalid one,
    /// or the failure's status.
    ///
    /// - Parameter outcome: How the check ended.
    private func finish(_ outcome: ValidateCommand.Outcome) {
        if let number = stoppingSignal.withLock({ $0 }) { SignalTrap.exit(by: number) }
        if case .failed(let failure) = outcome { CommandLineTool.fail(failure) }
        exit((outcome.exit ?? .software).rawValue)
    }
}
