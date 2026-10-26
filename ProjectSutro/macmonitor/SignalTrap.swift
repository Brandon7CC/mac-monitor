//
//  SignalTrap.swift
//  macmonitor
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import os
import SutroESFramework


// MARK: - Signals
/// Stops a command on the first `SIGINT`, `SIGTERM` or `SIGHUP` and exits at once on a second, then lets `macmonitor`
/// exit by the signal once the command has stopped: the shell then sees 130 for Ctrl-C, as it would for any other
/// command.
final class SignalTrap {
    /// The one trap this process has: it keeps the sources alive.
    private static var current: SignalTrap?
    /// The signal that started the stop, if one did. Any thread may read it.
    let stoppingSignal = OSAllocatedUnfairLock<Int32?>(initialState: nil)
    /// Keeps the sources alive.
    private var sources: [DispatchSourceSignal] = []
    
    /// Ignore the signals' default actions, and stop on the first one instead.
    ///
    /// - Parameter stop: Called on the main queue with the first signal, after it's recorded.
    /// - Returns: The trap.
    static func start(stop: @escaping (Int32) -> Void = { _ in }) -> SignalTrap {
        let trap = SignalTrap()
        current = trap
        trap.sources = [SIGINT, SIGTERM, SIGHUP].map { number in
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak trap] in trap?.received(number, stop: stop) }
            source.resume()
            return source
        }
        return trap
    }
    
    /// Stop on the first signal; exit on the second.
    ///
    /// - Parameters:
    ///   - number: The signal.
    ///   - stop: Stops the command.
    private func received(_ number: Int32, stop: (Int32) -> Void) {
        let first = stoppingSignal.withLock { stopping in
            defer { stopping = stopping ?? number }
            return stopping == nil
        }
        guard first else { _exit(128 + number) }
        stop(number)
    }
    
    /// Exit the way a command ended: by the signal that stopped it (restoring its default action and raising it), else
    /// with the failure's status, else `status`. A reader that went away after the signal (Ctrl-C stops `| jq` too)
    /// still exits by the signal.
    ///
    /// - Parameters:
    ///   - failure: Why the command failed, if it did.
    ///   - status: How it exits otherwise.
    /// - Returns: Never.
    func finish(_ failure: CommandLineFailure? = nil, status: CommandLineExit = .success) -> Never {
        if let number = stoppingSignal.withLock({ $0 }) {
            signal(number, SIG_DFL)
            raise(number)
            exit(128 + number)
        }
        if let failure { CommandLineTool.fail(failure) }
        exit(status.rawValue)
    }
}
