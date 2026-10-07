//
//  Message+LaunchedByParent.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Launched by parent
extension Message {
    /// The launched-by parent of the process this event created: an exec's target or a fork's child. `nil` for any
    /// other event, and until it's resolved.
    public var createdLaunchedByParent: LaunchedByParent? {
        switch event {
        case .exec(let exec): exec.launched_by_parent
        case .fork(let fork): fork.launched_by_parent
        default: nil
        }
    }
    
    /// Set the launched-by parent of the process this event created. Does nothing to any other event.
    ///
    /// - Parameter launchedByParent: The launched-by parent.
    mutating func setLaunchedByParent(_ launchedByParent: LaunchedByParent?) {
        switch event {
        case .exec(var exec):
            exec.launched_by_parent = launchedByParent
            event = .exec(exec)
        case .fork(var fork):
            fork.launched_by_parent = launchedByParent
            event = .fork(fork)
        default:
            break
        }
    }
    
    /// Resolve the launched-by parent of the process this event created from the event's own fields (see
    /// ``LaunchedByParent/resolve(_:by:path:)``), unless it already has one: the Security Extension's, or the one a
    /// trace carries, is never replaced.
    ///
    /// The Security Extension calls this as it serializes each event, Mac Monitor for an event from a Security
    /// Extension that didn't, and the importer for a trace that doesn't carry one (``TraceLaunchedByParents``).
    ///
    /// - Parameters:
    ///   - resolvedBy: Who is resolving.
    ///   - path: Names a process's executable from its pid and, when known, its token: a capture lane's
    ///     ``ProcessPathMemory``, which reads ``ProcessPath/live`` for a process it hasn't seen, or a trace's own
    ///     processes.
    mutating func resolveLaunchedByParent(by resolvedBy: LaunchedByParent.ResolvedBy,
                                          path: (Int32, AuditToken?) -> String?) {
        switch event {
        case .exec(var exec) where exec.launched_by_parent == nil:
            /// The exec's instigator is the image before: launchd's `xpcproxy` for a job's program.
            let byXPCProxy = LaunchedByParent.Lineage.isXPCProxy(process)
            let lineage = LaunchedByParent.Lineage(created: exec.target,
                                                   by: .exec(env: exec.env, byXPCProxy: byXPCProxy))
            exec.launched_by_parent = LaunchedByParent.resolve(lineage, by: resolvedBy, path: path)
            event = .exec(exec)
        case .fork(var fork) where fork.launched_by_parent == nil:
            /// The fork's instigator is the child's Unix parent.
            let lineage = LaunchedByParent.Lineage(created: fork.child, by: .fork(parentPath: process.executable?.path))
            fork.launched_by_parent = LaunchedByParent.resolve(lineage, by: resolvedBy, path: path)
            event = .fork(fork)
        default:
            break
        }
    }
}

