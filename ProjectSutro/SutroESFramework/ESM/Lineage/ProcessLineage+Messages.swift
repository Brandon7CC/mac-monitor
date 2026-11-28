//
//  ProcessLineage+Messages.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation
import EndpointSecurity


// MARK: - Endpoint Security's messages
extension ProcessLineage {
    /// Reads an exec's arguments. A test's messages have none Endpoint Security can read.
    typealias ArgumentReader = (inout es_event_exec_t) -> [String]

    /// Take in one of Endpoint Security's messages: a fork, an exec or an exit. Any other event changes nothing.
    ///
    /// - Parameters:
    ///   - message: The message. Only valid during the call.
    ///   - now: The time, in seconds on any clock that doesn't go back.
    ///   - arguments: Reads an exec's arguments.
    func note(_ message: UnsafePointer<es_message_t>, at now: TimeInterval,
              arguments: ArgumentReader = ProcessHelpers.parseExecArgs(execEvent:)) {
        let process = ProcessKey(message.pointee.process.pointee.audit_token)
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_FORK:
            let child = message.pointee.event.fork.child.pointee.audit_token
            fork(ProcessKey(child), from: process, token: child)
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            var event = message.pointee.event.exec
            let target = event.target.pointee
            exec(ProcessProgram(target, arguments: arguments(&event)), replacing: process,
                 parent: ProcessKey(target.parent_audit_token), token: target.audit_token, at: now)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            exit(process, at: now)
        default:
            break
        }
        told(upTo: message.pointee.mach_time)
    }
}


extension ProcessKey {
    /// - Parameter token: A process's audit token, as Endpoint Security gives it.
    init(_ token: audit_token_t) {
        self.init(pid: audit_token_to_pid(token), pidversion: audit_token_to_pidversion(token))
    }
}


extension ProcessProgram {
    /// The program an exec starts, with the values its exec record has (``Process``, ``ProcessExecEvent``).
    ///
    /// - Parameters:
    ///   - target: The exec's target.
    ///   - arguments: The exec's arguments.
    init(_ target: es_process_t, arguments: [String]) {
        let executable = target.executable.pointee
        self.init(key: ProcessKey(target.audit_token), path: executable.path.string ?? "",
                  commandLine: Self.commandLine(arguments), signingID: target.signing_id.string,
                  teamID: target.team_id.string, codesigningType: Self.codesigningType(of: target).rawValue)
    }

    /// - Parameter arguments: A program's arguments.
    /// - Returns: Its command line, as an exec record's `command_line` has it.
    static func commandLine(_ arguments: [String]) -> String {
        arguments.joined(separator: " ").trimmingCharacters(in: .whitespaces)
    }

    /// How a process is signed, as its record's `codesigning_type` says: from its flags where they tell, else from
    /// its executable's certificates, which are read once for each file (``CodeSigningCertificateCache``).
    ///
    /// - Parameter process: The process.
    /// - Returns: The type.
    static func codesigningType(of process: es_process_t) -> CodeSigningType {
        if process.is_platform_binary { return .platform }
        if process.codesigning_flags & UInt32(CS_ADHOC) != 0 { return .adhoc }
        if process.codesigning_flags & UInt32(CS_VALID) == 0 { return .unsigned }
        let executable = process.executable.pointee
        let path = executable.path.string ?? ""
        return path.isEmpty ? .unsigned : ProcessHelpers.certificateType(at: path, stat: Stat(from: executable.stat))
    }
}
