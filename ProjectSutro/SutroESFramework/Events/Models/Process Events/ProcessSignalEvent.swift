//
//  ProcessSignalEvent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//

import Foundation
import EndpointSecurity
import OSLog

import Darwin

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
    public var id: UUID = UUID()
    public var sig: Int
    public var signal_name: String
    
    public var instigator: Process?
    public var target: Process
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(target.audit_token)
        hasher.combine(sig)
    }
    
    public static func == (lhs: ProcessSignalEvent, rhs: ProcessSignalEvent) -> Bool {
        guard lhs.target.audit_token_string == rhs.target.audit_token_string &&
              lhs.sig == rhs.sig else {
            return false
        }
        
        switch (lhs.instigator, rhs.instigator) {
        case (.none, .none):
            return true
        case (.some(let leftInstigator), .some(let rightInstigator)):
            return leftInstigator.audit_token_string == rightInstigator.audit_token_string
        default:
            return false
        }
    }
    
    init(from rawMessage: UnsafePointer<es_message_t>) {
        // Getting the signal event
        let signalEvent: es_event_signal_t = rawMessage.pointee.event.signal
        
        self.sig = Int(signalEvent.sig)
        self.signal_name = signalName(from: signalEvent.sig)
        
        if let instigator = signalEvent.instigator {
            self.instigator = Process(from: instigator.pointee, version: Int(rawMessage.pointee.version))
        }
        
        self.target = Process(from: signalEvent.target.pointee, version: Int(rawMessage.pointee.version))
    }
}
