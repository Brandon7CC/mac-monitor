//
//  ProcessParents.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - A step up the launched-by parents
/// One step up a process's launched-by parents: the launched-by parent the process names, and the event that created
/// that parent.
public struct LaunchedByParentStep {
    /// The launched-by parent, as the process below it names it.
    public let launchedByParent: LaunchedByParent
    /// The exec (or, without one, the fork) that created the launched-by parent, or `nil` when the store doesn't have
    /// it: it started before recording (as launchd did), or LaunchServices named no launcher.
    public let event: ESMessage?
    
    /// The launched-by parent's executable: its creator's target or child, else what the answer names. Read on the
    /// event's context queue.
    public var path: String? {
        event?.created_path ?? launchedByParent.path
    }
}


// MARK: - Both parents
/// The Unix parent and the launched-by parent of the process an exec or fork created, as Event Facts shows them side by
/// side.
public struct ProcessParents {
    /// The Unix parent, as the message names it.
    public struct UnixParent {
        /// Its pid: the process's `ppid` (the forking process's pid, for a fork).
        public let pid: Int32
        /// The process's `original_ppid`: its parent's pid when it was created. It differs from ``pid`` once launchd
        /// adopts the process.
        public let original_ppid: Int32
        /// Its executable, when known.
        public let path: String?
    }
    
    /// The Unix parent.
    public let unix: UnixParent
    /// The launched-by parent, or `nil` when the event has none.
    public let launchedByParent: LaunchedByParentStep?
    
    /// Is the launched-by parent the Unix parent itself? Then Event Facts shows them as one.
    public var launchedByParentIsUnixParent: Bool {
        guard let answer = launchedByParent?.launchedByParent else { return false }
        return answer.source == .unixParent && answer.pid == unix.pid
    }
}
