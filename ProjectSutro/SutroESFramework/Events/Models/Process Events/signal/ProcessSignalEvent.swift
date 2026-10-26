//
//  ProcessSignalEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation


/// Each signal's name by its number, from `<sys/signal.h>`: 1 (`SIGHUP`) to 31 (`SIGUSR2`), and "IS-ALIVE" for 0,
/// which only checks that the target exists.
private let signalNames = [
    "IS-ALIVE", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGEMT", "SIGFPE", "SIGKILL",
    "SIGBUS", "SIGSEGV", "SIGSYS", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGURG", "SIGSTOP", "SIGTSTP", "SIGCONT",
    "SIGCHLD", "SIGTTIN", "SIGTTOU", "SIGIO", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGINFO",
    "SIGUSR1", "SIGUSR2",
]

/// A signal's name.
///
/// - Parameter signalNumber: The signal's number.
/// - Returns: Its name in `signalNames`, or "UNKNOWN".
func signalName(from signalNumber: Int32) -> String {
    signalNames.indices.contains(Int(signalNumber)) ? signalNames[Int(signalNumber)] : "UNKNOWN"
}

/**
 * @brief Send a signal to a process
 *
 * Signals may be sent on behalf of another process or directly. Notably launchd often sends signals
 * on behalf of another process for service start/stop operations. If this is the case an
 * instigator will be provided. The relationship between each process is illustrated below:
 *
 * Delegated Signal:
 *
 *     Instigator Process -> IPC to Sender Process (launchd) -> Target Process
 *
 * Direct Signal:
 *
 *     Sender Process -> Target Process
 *
 * Clients may wish to block delegated signals from launchd for non-authorized instigators, while still
 * allowing direct signals initiated by launchd for shutdown/reboot/restart.
 *
 * @field sig              The signal number to be delivered
 * @field target           The process that will receive the signal
 * @field instigator       Process information for the instigator (if applicable).
 *
 * @note This event will not fire if a process sends a signal to itself.
 * @note This event type does not support caching.
 * @note Be aware of the nullablity of some of the fields. The instigator may not be
 *       applicable.
 */

// MARK:  Process Signal event https://developer.apple.com/documentation/endpointsecurity/es_event_signal_t
public struct ProcessSignalEvent: Codable, IdentityHashable {
    public var id: UUID = UUID.buffered()
    public var sig: Int
    public var signal_name = ""
    
    public var instigator: Process?
    public var target: Process
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the signal event
        let signalEvent: es_event_signal_t = rawMessage.pointee.event.signal
        
        self.sig = Int(signalEvent.sig)
        
        /// Message version 9 and later: before it, these bytes are reserved and can't be read as a process.
        instigator = rawMessage.pointee.version >= 9
            ? signalEvent.instigator.map { Process(from: $0.pointee, version: Int(rawMessage.pointee.version)) } : nil
        
        self.target = Process(from: signalEvent.target.pointee, version: Int(rawMessage.pointee.version))
        enrich()
    }
}


// MARK: - Mac Monitor enrichment
extension ProcessSignalEvent: ESEnrichable {
    /// Derive the signal's name.
    public mutating func enrich() {
        signal_name = signalName(from: Int32(truncatingIfNeeded: sig))
    }
}
