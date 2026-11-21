//
//  Message+AncestorKeys.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - Ancestor keys
extension Message {
    /// Stamp an exec or a fork with the keys of the ancestors of the process it creates, nearest first. Any other
    /// event is left as it is: an event's process is found by the exec or fork that created it.
    ///
    /// The lineage table's own client may be behind the lane that calls this or ahead of it, so the lane tells the
    /// table of the event first (``ProcessLineage/note(_:at:)``). An exec then asks for its process as it was
    /// before the exec, whose ancestors are the target's too, and a fork names the forking process as the child's
    /// parent. Where the table knows neither, the parent the exec's target names stands in. A parent the table
    /// knows by its key alone is read from the system or waited for, as an indicator's lookup does
    /// (``ProcessLineage/ancestors(of:parent:reading:at:chain:)``), so the keys are the ancestors an indicator saw.
    ///
    /// - Parameter lineage: The table.
    /// - Returns: The ancestors it named, nearest first, or `nil` for an event that creates no process.
    @discardableResult
    mutating func stampAncestorKeys(from lineage: ProcessLineage) -> [ProcessProgram]? {
        guard let process = process.audit_token.map(ProcessKey.init) else { return nil }
        let ancestors: [ProcessProgram], time = UInt64(clamping: mach_time)
        switch event {
        case .exec(var exec):
            ancestors = lineage.ancestors(of: process, parent: exec.target.parent_audit_token.map(ProcessKey.init),
                                          reading: true, at: time)
            exec.ancestor_keys = ancestors.map(\.key.description)
            event = .exec(exec)
        case .fork(var fork):
            guard let child = fork.child.audit_token.map(ProcessKey.init) else { return nil }
            ancestors = lineage.ancestors(of: child, parent: process, reading: true, at: time)
            fork.ancestor_keys = ancestors.map(\.key.description)
            event = .fork(fork)
        default:
            return nil
        }
        return ancestors
    }
}


// MARK: - A capture lane's events
extension ProcessLineage {
    /// Take in a fork, an exec or an exit a capture lane built, as its own client takes in the message
    /// (``note(_:at:arguments:)``). The lane hands its events over in Endpoint Security's order, so once it has, the
    /// table knows every process those events created, however far along its own client is. Only the lane knows
    /// who really caused a process to run (``LaunchedByParent``), which it tells the table too.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - now: The time, in seconds on any clock that doesn't go back.
    func note(_ message: Message, at now: TimeInterval) {
        guard let process = message.process.audit_token.map(ProcessKey.init) else { return }
        switch message.event {
        case .fork(let fork):
            guard let child = fork.child.audit_token.map(ProcessKey.init) else { return }
            self.fork(child, from: process, launchedBy: Self.launcher(fork.launched_by_parent))
        case .exec(let exec):
            guard let key = exec.target.audit_token.map(ProcessKey.init) else { return }
            let target = exec.target
            self.exec(ProcessProgram(key: key, path: target.executable?.path ?? "", commandLine: exec.command_line,
                                     signingID: target.signing_id, teamID: target.team_id,
                                     codesigningType: target.codesigning_type.rawValue),
                      replacing: process, parent: target.parent_audit_token.map(ProcessKey.init),
                      launchedBy: Self.launcher(exec.launched_by_parent), at: now)
        case .exit:
            exit(process, at: now)
        default:
            break
        }
    }

    /// The process a launched-by parent names, as the launched-by chain follows it.
    ///
    /// - Parameter answer: A created process's launched-by parent.
    /// - Returns: Its key, with pid version 0 when only its pid is known, or `nil` when it's the Unix parent or
    ///   no process is named.
    static func launcher(_ answer: LaunchedByParent?) -> ProcessKey? {
        guard let answer, answer.source != .unixParent else { return nil }
        if let token = answer.audit_token { return ProcessKey(token) }
        return answer.pid.map { ProcessKey(pid: $0, pidversion: 0) }
    }
}



// MARK: - A process as an event says it
extension ProcessProgram {
    /// A program as an event's own record of its process has it: its path and signature. Its command line is only
    /// in its exec.
    ///
    /// - Parameter process: An event's process.
    init?(_ process: Process) {
        guard let token = process.audit_token, let path = process.executable?.path else { return nil }
        self.init(key: ProcessKey(token), path: path, signingID: process.signing_id, teamID: process.team_id,
                  codesigningType: process.codesigning_type.rawValue)
    }
}
