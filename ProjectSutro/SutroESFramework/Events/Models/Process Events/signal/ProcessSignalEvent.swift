//
//  ProcessSignalEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation


func signalName(from signalNumber: Int32) -> String {
    switch signalNumber {
    case SIGHUP:
        return "SIGHUP"
    case SIGINT:
        return "SIGINT"
    case SIGQUIT:
        return "SIGQUIT"
    case SIGILL:
        return "SIGILL"
    case SIGTRAP:
        return "SIGTRAP"
    case SIGABRT:
        return "SIGABRT"
    case SIGEMT:
        return "SIGEMT"
    case SIGFPE:
        return "SIGFPE"
    case SIGKILL:
        return "SIGKILL"
    case SIGBUS:
        return "SIGBUS"
    case SIGSEGV:
        return "SIGSEGV"
    case SIGSYS:
        return "SIGSYS"
    case SIGPIPE:
        return "SIGPIPE"
    case SIGALRM:
        return "SIGALRM"
    case SIGTERM:
        return "SIGTERM"
    case SIGURG:
        return "SIGURG"
    case SIGSTOP:
        return "SIGSTOP"
    case SIGTSTP:
        return "SIGTSTP"
    case SIGCONT:
        return "SIGCONT"
    case SIGCHLD:
        return "SIGCHLD"
    case SIGTTIN:
        return "SIGTTIN"
    case SIGTTOU:
        return "SIGTTOU"
    case SIGIO:
        return "SIGIO"
    case SIGXCPU:
        return "SIGXCPU"
    case SIGXFSZ:
        return "SIGXFSZ"
    case SIGVTALRM:
        return "SIGVTALRM"
    case SIGPROF:
        return "SIGPROF"
    case SIGWINCH:
        return "SIGWINCH"
    case SIGINFO:
        return "SIGINFO"
    case SIGUSR1:
        return "SIGUSR1"
    case SIGUSR2:
        return "SIGUSR2"
    case 0:
        return "IS-ALIVE"
    default:
        return "UNKNOWN"
    }
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
public struct ProcessSignalEvent: Identifiable, Codable, Hashable {
    public var id: UUID = UUID.buffered()
    public var sig: Int
    public var signal_name = ""
    
    public var instigator: Process?
    public var target: Process
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    public static func == (lhs: ProcessSignalEvent, rhs: ProcessSignalEvent) -> Bool {
        return lhs.id == rhs.id
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the signal event
        let signalEvent: es_event_signal_t = rawMessage.pointee.event.signal
        
        self.sig = Int(signalEvent.sig)
        
        /// Message version 9 and later: before it, these bytes are reserved and can't be read as a process.
        if rawMessage.pointee.version >= 9, let instigator = signalEvent.instigator {
            self.instigator = Process(from: instigator.pointee, version: Int(rawMessage.pointee.version))
        }
        
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
