//
//  ValidateRunner.swift
//  macmonitor
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import SutroESFramework


// MARK: - Validate runner
/// `macmonitor validate`, as a process: standard output, signals, and the exit status. The check itself is
/// ``ValidateCommand``'s.
///
/// **Stopping:** the check runs off the main queue, so a signal can reach it. The first `SIGINT`, `SIGTERM` or
/// `SIGHUP` stops it before its next record; the report so far is written, saying it stopped, and `macmonitor` exits
/// by that signal (130 for Ctrl-C), as a stream does. A second signal exits at once.
enum ValidateRunner {
    /// Start checking. Runs until it exits, on the main queue.
    ///
    /// - Parameter invocation: The trace, and which of its keys to check.
    static func start(_ invocation: ValidateInvocation) {
        let trap = SignalTrap.start(), output = FileOutput(descriptor: STDOUT_FILENO)
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = ValidateCommand.run(invocation, output: output,
                                              isCancelled: { trap.stoppingSignal.withLock { $0 != nil } })
            /// 0 for a valid trace, 65 for an invalid one, or the failure's status.
            DispatchQueue.main.async {
                if case .failed(let failure) = outcome { trap.finish(failure) }
                trap.finish(status: outcome.exit ?? .software)
            }
        }
    }
}
