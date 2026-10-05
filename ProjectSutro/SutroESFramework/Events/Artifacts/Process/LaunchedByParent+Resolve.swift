//
//  LaunchedByParent+Resolve.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Lineage
extension LaunchedByParent {
    /// What an exec or fork message says about the parents of the process it creates. Every field is in the message
    /// (message version 4 and later, so on every macOS Mac Monitor supports), so resolving needs no lookups.
    struct Lineage {
        /// How the process was created, which says what else the message knows about its parents.
        enum Creation {
            /// An exec, with the new image's environment and whether launchd's `xpcproxy` exec'd it
            /// (``isXPCProxy(_:)``): `xpcproxy` puts the label of the job it starts in the environment.
            case exec(env: [String], byXPCProxy: Bool)
            /// A fork, with the forking process's executable: the forking process is the child's Unix parent, so
            /// the message names it itself.
            case fork(parentPath: String?)
        }
        
        /// The created process's pid.
        let pid: Int32
        /// Its parent's pid, and its parent's pid when it was created (they differ once launchd adopts it).
        let ppid, original_ppid: Int32
        /// Its parent's and its responsible process's audit tokens.
        let parent_audit_token, responsible_audit_token: AuditToken?
        /// How it was created.
        let creation: Creation
        
        /// - Parameters:
        ///   - pid: The created process's pid.
        ///   - ppid: `ppid`.
        ///   - original_ppid: `original_ppid`.
        ///   - parent_audit_token: `parent_audit_token`.
        ///   - responsible_audit_token: `responsible_audit_token`.
        ///   - creation: How the process was created.
        init(pid: Int32, ppid: Int32, original_ppid: Int32, parent_audit_token: AuditToken?,
             responsible_audit_token: AuditToken?, by creation: Creation) {
            self.pid = pid
            self.ppid = ppid
            self.original_ppid = original_ppid
            self.parent_audit_token = parent_audit_token
            self.responsible_audit_token = responsible_audit_token
            self.creation = creation
        }
        
        /// - Parameters:
        ///   - process: The exec's target or the fork's child.
        ///   - creation: How it was created.
        init(created process: Process, by creation: Creation) {
            self.init(pid: process.audit_token?.pid ?? process.pid, ppid: process.ppid,
                      original_ppid: process.original_ppid, parent_audit_token: process.parent_audit_token,
                      responsible_audit_token: process.responsible_audit_token, by: creation)
        }
        
        /// The label of the launchd job that started the process: `XPC_SERVICE_NAME` in the environment of an exec by
        /// `xpcproxy` (``ProcessExecEvent/xpcServiceName(in:)``). An image any other process exec'd, even a job's own
        /// program exec'ing again, has whatever environment that process chose, so its label names no job.
        var jobLabel: String? {
            guard case .exec(let env, byXPCProxy: true) = creation else { return nil }
            return ProcessExecEvent.xpcServiceName(in: env)
        }
        
        /// Is the exec'ing process launchd's `xpcproxy`, which execs each job's program with the job's environment?
        /// Only the platform binary at its path is.
        ///
        /// - Parameter process: The exec's instigator: the image before the new one.
        /// - Returns: `true` for `xpcproxy`.
        static func isXPCProxy(_ process: Process) -> Bool {
            process.is_platform_binary && process.executable?.path == xpcProxyPath
        }
        
        /// `xpcproxy`'s executable.
        static let xpcProxyPath = "/usr/libexec/xpcproxy"
    }
}


// MARK: - Resolving
extension LaunchedByParent {
    /// launchd's pid.
    static let launchdPID: Int32 = 1
    /// launchd's executable.
    static let launchdPath = "/sbin/launchd"
    
    /// Is the launched-by parent launchd (pid 1)?
    public var isLaunchd: Bool {
        pid == Self.launchdPID
    }
    
    /// The launched-by parent a message names on its own: what the Security Extension stamps as it serializes an event,
    /// and what Mac Monitor resolves for an event or trace that doesn't carry one.
    ///
    /// In order:
    /// 1. ``Source/unixParent`` when the Unix parent isn't launchd: `parent_audit_token`, or `ppid` without one.
    /// 2. ``Source/unixParent`` by `original_ppid` alone when launchd adopted the process before its exec (that parent
    ///    has exited, so neither its token nor its path is known).
    /// 3. ``Source/responsibleProcess`` when the responsible process isn't the process itself or launchd.
    /// 4. ``Source/launchdJob`` for a direct launchd child that `xpcproxy` exec'd with a job label.
    /// 5. Otherwise the Unix parent: launchd, with nothing better (a launchd fork, `xpcproxy`).
    ///
    /// A direct launchd child's job label rides along with steps 3 and 4. It's only read for a direct launchd child
    /// that `xpcproxy` exec'd (``Lineage/jobLabel``): any other process inherited the variable, or chose it. A job's
    /// program that execs again keeps launchd as its parent, but its new image names no job. ``Source/launchServices``
    /// is never answered here: an app hasn't checked in with LaunchServices when it's exec'd, so Mac Monitor asks
    /// later (``needsLaunchServices``).
    ///
    /// - Parameters:
    ///   - lineage: The created process's lineage.
    ///   - resolvedBy: Who is resolving.
    ///   - path: Names a process's executable from its pid and, when known, its token: a capture lane looks the token
    ///     up among the processes it has seen and otherwise reads it now (``ProcessPathMemory``, ``ProcessPath``), a
    ///     trace import looks it up in the trace. Never called for launchd, nor for a fork's parent (the message
    ///     names it).
    /// - Returns: The launched-by parent.
    static func resolve(_ lineage: Lineage, by resolvedBy: ResolvedBy,
                        path: (Int32, AuditToken?) -> String?) -> LaunchedByParent {
        let parent = lineage.parent_audit_token
        let parentPID = parent?.pid ?? lineage.ppid
        if parentPID > launchdPID {
            let parentPath: String?
            switch lineage.creation {
            case .exec: parentPath = path(parentPID, parent)
            case .fork(let forkingPath): parentPath = forkingPath
            }
            return LaunchedByParent(source: .unixParent, audit_token: parent, pid: parentPID, path: parentPath,
                                    resolved_by: resolvedBy)
        }
        let original = lineage.original_ppid
        if parentPID == launchdPID, original > launchdPID, original != lineage.pid {
            return LaunchedByParent(source: .unixParent, audit_token: nil, pid: original, path: nil,
                                    resolved_by: resolvedBy)
        }
        let job = parentPID == launchdPID ? lineage.jobLabel.map(LaunchdJob.init(label:)) : nil
        if let responsible = lineage.responsible_audit_token, responsible.pid > launchdPID,
           responsible.pid != lineage.pid {
            return LaunchedByParent(source: .responsibleProcess, audit_token: responsible,
                                    path: path(responsible.pid, responsible), launchd_job: job,
                                    resolved_by: resolvedBy)
        }
        if let job {
            return LaunchedByParent(source: .launchdJob, audit_token: parent, pid: launchdPID, path: launchdPath,
                                    launchd_job: job, resolved_by: resolvedBy)
        }
        return LaunchedByParent(source: .unixParent, audit_token: parent, pid: parentPID,
                                path: parentPID == launchdPID ? launchdPath : nil, resolved_by: resolvedBy)
    }
    
    /// Should Mac Monitor ask LaunchServices who launched the app? For an answer that isn't the Unix parent and names
    /// an app instance's job (`application.…`): LaunchServices' launcher comes before the responsible process.
    public var needsLaunchServices: Bool {
        source != .unixParent && launchd_job?.label.hasPrefix("application.") == true
    }
}


// MARK: - Process paths
/// Executable paths of live processes, for naming a launched-by parent the message doesn't name.
enum ProcessPath {
    /// The most bytes `proc_pidpath` writes: `PROC_PIDPATHINFO_MAXSIZE`, which Swift doesn't import.
    static let capacity = 4 * Int(MAXPATHLEN)
    
    /// ``of(_:)`` as a resolver's `path`: reads the pid now, and ignores the token.
    static let live: (Int32, AuditToken?) -> String? = { pid, _ in of(pid) }
    
    /// The executable of a process, now.
    ///
    /// The public SDK can't read a pid's pidversion, so this can't be checked against an audit token: the caller reads
    /// it while the process is known to be alive (as its event is handled) and keeps the token as the identity.
    ///
    /// - Parameter pid: A process ID.
    /// - Returns: Its executable's path, or `nil` when it has exited or can't be read.
    static func of(_ pid: Int32) -> String? {
        guard pid > 0 else { return nil }
        return withUnsafeTemporaryAllocation(of: CChar.self, capacity: capacity) { buffer in
            guard let base = buffer.baseAddress, proc_pidpath(pid, base, UInt32(buffer.count)) > 0 else { return nil }
            return String(cString: base)
        }
    }
}
