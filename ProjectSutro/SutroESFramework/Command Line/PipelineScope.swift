//
//  PipelineScope.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Ancestors
/// A process in `macmonitor`'s ancestry.
public struct PipelineAncestor: Equatable, Sendable {
    /// Its process ID.
    public let pid: pid_t
    /// Its process group.
    public let groupID: pid_t
    /// Its executable's path, or empty if it couldn't be read.
    public let path: String
    
    /// - Parameters:
    ///   - pid: The process ID.
    ///   - groupID: The process group.
    ///   - path: The executable's path.
    public init(pid: pid_t, groupID: pid_t, path: String) {
        self.pid = pid
        self.groupID = groupID
        self.path = path
    }
}


// MARK: - Pipeline scope
/// Which events are `macmonitor`'s own pipeline's, so a stream piped into `jq` doesn't fill up with `jq`'s own reads.
///
/// The shell runs a pipeline (`sudo macmonitor stream | jq .`) in one process group. Under `sudo`, `macmonitor` itself
/// runs in another: sudo 1.9.14 and later run the command in a new session behind a monitor process (`use_pty`). So
/// the scope walks up from `macmonitor` through every consecutive `/usr/bin/sudo` ancestor and suppresses the process
/// groups it passes, stopping at the first other ancestor (the shell, whose own group is never suppressed). Group 0
/// and launchd's group 1 are never suppressed. `macmonitor`'s own process is always suppressed, even with
/// `--include-self`, so writing to a file can't feed back into the stream.
///
/// Suppression happens in `macmonitor`, after drop accounting: the Security Extension still sends these events, so
/// every `global_seq_num` gap stays a real drop. Like eslogger's, it's a heuristic: a script without job control
/// shares its group with `macmonitor`, so the script's own events are hidden too; `--include-self` shows them.
public struct PipelineScope: Equatable, Sendable {
    /// The path of `sudo`.
    public static let sudoPath = "/usr/bin/sudo"
    /// How far up the ancestry the live walk goes.
    static let maximumDepth = 16
    
    /// `macmonitor`'s process ID: always suppressed.
    public let ownPID: pid_t
    /// The process groups suppressed.
    public let groups: Set<pid_t>
    
    /// The scope for an ancestry.
    ///
    /// - Parameters:
    ///   - ancestry: `macmonitor` first, then its parent, grandparent, and so on, at least as far as the first ancestor
    ///     that isn't `sudo`.
    ///   - includeSelf: Show the pipeline's events (`--include-self`): only `macmonitor`'s own process is suppressed.
    public init(ancestry: [PipelineAncestor], includeSelf: Bool) {
        ownPID = ancestry.first?.pid ?? getpid()
        guard !includeSelf, let own = ancestry.first else {
            groups = []
            return
        }
        let sudos = ancestry.dropFirst().prefix { $0.path == Self.sudoPath }
        groups = Set(([own] + sudos).map(\.groupID).filter { $0 > 1 })
    }
    
    /// The scope for this process, from its live ancestry.
    ///
    /// - Parameter includeSelf: Show the pipeline's events (`--include-self`).
    /// - Returns: The scope.
    public static func current(includeSelf: Bool) -> PipelineScope {
        PipelineScope(ancestry: ancestry(from: getpid()), includeSelf: includeSelf)
    }
    
    /// Is an event the pipeline's own?
    ///
    /// - Parameter header: The event's header.
    /// - Returns: `true` to leave it out of the output.
    public func suppresses(_ header: EventHeader) -> Bool {
        header.process.pid == ownPID || groups.contains(header.process.groupID)
    }
    
    /// A process and its ancestors, as far as the first one after it that isn't `sudo`.
    ///
    /// - Parameter pid: The process to start from.
    /// - Returns: The process, then its ancestors. Empty if the process can't be read.
    static func ancestry(from pid: pid_t) -> [PipelineAncestor] {
        var ancestry: [PipelineAncestor] = []
        var next = pid
        while ancestry.count < maximumDepth, next > 0, let entry = read(next) {
            ancestry.append(entry.ancestor)
            guard ancestry.count == 1 || entry.ancestor.path == sudoPath, entry.parent != next else { break }
            next = entry.parent
        }
        return ancestry
    }
    
    /// A process's group, path, and parent, from `libproc`.
    ///
    /// - Parameter pid: The process.
    /// - Returns: The process and its parent's process ID, or `nil` if it can't be read (it exited).
    private static func read(_ pid: pid_t) -> (ancestor: PipelineAncestor, parent: pid_t)? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        /// `PROC_PIDPATHINFO_MAXSIZE`.
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &path, UInt32(path.count))
        let ancestor = PipelineAncestor(pid: pid, groupID: pid_t(info.pbi_pgid),
                                        path: length > 0 ? String(cString: path) : "")
        return (ancestor, pid_t(info.pbi_ppid))
    }
}
