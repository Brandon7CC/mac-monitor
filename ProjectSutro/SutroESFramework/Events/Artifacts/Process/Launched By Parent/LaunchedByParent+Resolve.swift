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


extension LaunchedByParent.Lineage {
    /// - Parameters:
    ///   - process: The exec's target or the fork's child.
    ///   - creation: How it was created.
    init(created process: Process, by creation: Creation) {
        self.init(pid: process.audit_token?.pid ?? process.pid, ppid: process.ppid,
                  original_ppid: process.original_ppid, parent_audit_token: process.parent_audit_token,
                  responsible_audit_token: process.responsible_audit_token, creation: creation)
    }

    /// The parent's pid. It's the token's pid, or `ppid` without a token.
    var parentPID: Int32 { parent_audit_token?.pid ?? ppid }
    /// Is launchd the parent?
    var isLaunchdChild: Bool { parentPID == LaunchedByParent.launchdPID }
    /// Is the parent a process other than launchd? Check 1.
    var hasUnixParent: Bool { parentPID > LaunchedByParent.launchdPID }

    /// The pid of the parent launchd adopted the process from, or `nil`. That parent has exited. Check 2.
    var adoptedFrom: Int32? {
        let original = original_ppid
        return isLaunchdChild && original > LaunchedByParent.launchdPID && original != pid ? original : nil
    }

    /// The responsible process, or `nil` when it's launchd or the process itself. Check 3.
    var responsibleProcess: AuditToken? {
        guard let responsible = responsible_audit_token, responsible.pid > LaunchedByParent.launchdPID,
              responsible.pid != pid else { return nil }
        return responsible
    }

    /// The launchd job that started the process. Only a direct launchd child has one. Check 4.
    var launchdJob: LaunchedByParent.LaunchdJob? {
        isLaunchdChild ? jobLabel.map(LaunchedByParent.LaunchdJob.init(label:)) : nil
    }

    /// The parent's executable. A fork's message names it, and an exec's is looked up.
    ///
    /// - Parameter path: Names a process's executable from its pid and token.
    /// - Returns: The path, or `nil` when it isn't known.
    func parentPath(_ path: (Int32, AuditToken?) -> String?) -> String? {
        if case .fork(let forkingPath) = creation { return forkingPath }
        return path(parentPID, parent_audit_token)
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
        let answer = { (source: Source, token: AuditToken?, pid: Int32?, executable: String?, job: LaunchdJob?) in
            LaunchedByParent(source: source, audit_token: token, pid: pid, path: executable, launchd_job: job,
                             resolved_by: resolvedBy)
        }
        let parent = lineage.parent_audit_token, parentPID = lineage.parentPID
        // 1. A Unix parent that isn't launchd
        if lineage.hasUnixParent { return answer(.unixParent, parent, parentPID, lineage.parentPath(path), nil) }
        // 2. The parent launchd adopted the process from. Only its pid is known.
        if let original = lineage.adoptedFrom { return answer(.unixParent, nil, original, nil, nil) }
        // 3. The responsible process. It carries the job's label on to Launch Services.
        let job = lineage.launchdJob
        if let responsible = lineage.responsibleProcess {
            return answer(.responsibleProcess, responsible, nil, path(responsible.pid, responsible), job)
        }
        // 4. launchd, starting a job
        if let job { return answer(.launchdJob, parent, launchdPID, launchdPath, job) }
        // 5. launchd itself, or a parent pid of 0 or less
        return answer(.unixParent, parent, parentPID, lineage.isLaunchdChild ? launchdPath : nil, nil)
    }
    
    /// Should Mac Monitor ask LaunchServices who launched the app? For an answer that isn't the Unix parent and names
    /// an app instance's job (an `application.` label): LaunchServices' launcher comes before the responsible process.
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
