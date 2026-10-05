//
//  SignalTrap.swift
//  macmonitor
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Signals
/// Turns `SIGINT`, `SIGTERM` and `SIGHUP` into calls on a queue, so a stream can stop cleanly, and lets `macmonitor`
/// exit by the signal once it has: the shell then sees 130 for Ctrl-C, as it would for any other command.
final class SignalTrap {
    /// The signals a stream stops on.
    static let stopping: [Int32] = [SIGINT, SIGTERM, SIGHUP]
    /// Keeps the sources alive.
    private let sources: [DispatchSourceSignal]
    
    /// Ignore the signals' default actions and call `handler` for each one instead.
    ///
    /// - Parameters:
    ///   - signals: The signals.
    ///   - queue: Where `handler` runs.
    ///   - handler: Called with each signal received.
    init(_ signals: [Int32] = stopping, queue: DispatchQueue = .main, handler: @escaping (Int32) -> Void) {
        sources = signals.map { number in
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: queue)
            source.setEventHandler { handler(number) }
            source.resume()
            return source
        }
    }
    
    /// Exit by a signal: restore its default action and raise it.
    ///
    /// - Parameter number: The signal.
    /// - Returns: Never, unless the signal's default action doesn't end the process.
    static func exit(by number: Int32) -> Never {
        signal(number, SIG_DFL)
        raise(number)
        Foundation.exit(128 + number)
    }
}
