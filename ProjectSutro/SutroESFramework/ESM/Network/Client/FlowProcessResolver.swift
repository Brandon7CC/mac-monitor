//
//  FlowProcessResolver.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A flow's process
/// The process a socket names, as far as it could be told apart from any other that had its pid.
struct FlowProcess: Sendable {
    /// What the process was when its socket's first update was read.
    enum State: Sendable {
        /// The kernel's own socket, pid 0.
        case kernel
        case live
        /// Exited but not yet reaped.
        case zombie
        /// Gone, or its pid already reused.
        case reaped
    }

    let pid: Int32
    /// The process's name, as the socket's descriptor has it.
    let name: String
    let state: State
    /// Exact when the descriptor's unique ID matched the process with the pid. Without one, the pid's process when the
    /// socket's first update was read.
    var key: ProcessKey?
    var token: audit_token_t?
    var program: ProcessProgram?
    var ppid, groupID, sessionID: Int32?

    /// Has it the signing values its exec record would have?
    var isSigned: Bool {
        program?.codesigningType != nil
    }

    /// Is there nothing the lineage table could add? The kernel's socket, and a process read with its token and
    /// signing values.
    var isSettled: Bool {
        state == .kernel || (state != .reaped && token != nil && isSigned)
    }
}


// MARK: - Resolving it
/// Tells which process a socket's descriptor names, on the client's read queue, from the reads that still answer
/// once the process has exited. When the descriptor gives a unique ID, it's checked against the pid's
/// (`PROC_PIDUNIQIDENTIFIERINFO`, which finds zombies too), so a reused pid never names the wrong process. Without one,
/// the descriptor names the process that has the pid now. Nothing here waits.
///
/// **Threading:** not thread-safe. Only the client's read queue uses it.
final class FlowProcessResolver {
    /// What it reads of a process, the live system's by default.
    struct Reads {
        /// The unique ID and pid version of the pid's process, zombie or not.
        var identity: (Int32) -> (upid: UInt64, pidversion: Int32)?
        /// Its parent's pid, its process group, and whether it's a zombie.
        var bsd: (Int32) -> (ppid: Int32, groupID: Int32, isZombie: Bool)?
        /// Its session, while it runs.
        var session: (Int32) -> Int32?
        /// Its audit token, while it runs.
        var token: (Int32) -> audit_token_t?
        /// Its executable's path, by its token.
        var path: (audit_token_t) -> String?
        /// Its signing values, by its token and path.
        var signing: (audit_token_t, String) -> FlowSigning?
        /// What the lineage table knows of it, without waiting.
        var program: (ProcessKey) -> ProcessProgram?

        static let live = Reads(identity: { pid in
            var info = mm_proc_uniqidentifierinfo()
            let size = Int32(MemoryLayout<mm_proc_uniqidentifierinfo>.size)
            guard proc_pidinfo(pid, MM_PROC_PIDUNIQIDENTIFIERINFO, 1, &info, size) == size else { return nil }
            return (info.p_uniqueid, info.p_idversion)
        }, bsd: { pid in
            var info = proc_bsdshortinfo()
            let size = Int32(MemoryLayout<proc_bsdshortinfo>.size)
            guard proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &info, size) == size else { return nil }
            return (Int32(bitPattern: info.pbsi_ppid), Int32(bitPattern: info.pbsi_pgid),
                    info.pbsi_status == UInt32(SZOMB))
        }, session: { pid in
            let session = getsid(pid)
            return session >= 0 ? session : nil
        }, token: RunningProcesses.token(of:), path: { ProcessPath.of(AuditToken(from: $0)) },
           signing: FlowSigning.read, program: { LineageMonitor.shared.table?.program($0) })
    }

    /// How many processes it remembers, by unique ID. Past it, it forgets them all.
    static let capacity = 1_024
    private let reads: Reads
    private var cache: [UInt64: FlowProcess] = [:]

    /// - Parameter reads: What it reads of a process.
    init(reads: Reads = .live) {
        self.reads = reads
    }

    /// The process a socket's descriptor names, read when its first update is.
    ///
    /// A delegated TCP socket gives its effective pid with no unique ID. That names the process that has the pid now.
    /// Pids rise until they wrap, so at the socket's first update that's the process it acts for.
    ///
    /// - Parameters:
    ///   - pid: The descriptor's pid.
    ///   - upid: Its unique ID, or 0 when it gives none.
    ///   - name: Its process name.
    /// - Returns: The process. A zombie's has its key, parent and group, and the rest comes on delivery.
    func resolve(pid: Int32, upid: UInt64, name: String) -> FlowProcess {
        guard pid > 0 else { return FlowProcess(pid: pid, name: name, state: .kernel) }
        guard let identity = reads.identity(pid), upid == 0 || identity.upid == upid else {
            return FlowProcess(pid: pid, name: name, state: .reaped)
        }
        let key = ProcessKey(pid: pid, pidversion: identity.pidversion)
        if var known = cache[identity.upid], known.key == key {
            if !known.isSigned, let program = reads.program(key), program.isKnown {
                known.program = program
                cache[identity.upid] = known
            }
            return known
        }
        let bsd = reads.bsd(pid)
        let isLive = bsd?.isZombie == false
        var process = FlowProcess(pid: pid, name: name, state: isLive ? .live : .zombie, key: key,
                                  ppid: bsd?.ppid, groupID: bsd?.groupID)
        if isLive {
            process.sessionID = reads.session(pid)
            process.token = reads.token(pid).flatMap { audit_token_to_pidversion($0) == key.pidversion ? $0 : nil }
        }
        process.program = reads.program(key).flatMap { $0.isKnown ? $0 : nil } ?? process.token.flatMap { token in
            reads.path(token).map { path in
                let signing = reads.signing(token, path)
                return ProcessProgram(key: key, path: path, signingID: signing?.signingID, teamID: signing?.teamID,
                                      codesigningType: signing?.type.rawValue)
            }
        }
        if cache.count >= Self.capacity { cache.removeAll(keepingCapacity: true) }
        cache[identity.upid] = process
        return process
    }

    /// Forget every process, once the client closes.
    func removeAll() {
        cache = [:]
    }
}


// MARK: - Completing it on delivery
extension FlowProcess {
    /// Fill in from the lineage table what couldn't be read when the socket's first update was. That's the token
    /// and signing values of a process whose exec the table hadn't been told of yet, and of a zombie, and for a reaped
    /// process the pid's newest program, when its executable's name starts with the socket's process name. Pids rise
    /// until they wrap, so that's the same process unless it exec'd the same name again in its last milliseconds.
    ///
    /// Waits, within the table's patience and budget, until the table's own client is told of an event as late as
    /// the record (``ProcessLineage/program(_:toldUpTo:)``).
    ///
    /// - Parameters:
    ///   - lineage: The lineage table.
    ///   - time: The record's time, on Endpoint Security's clock.
    /// - Returns: `false` for a reaped process the table doesn't know.
    mutating func complete(from lineage: ProcessLineage, upTo time: Int64) -> Bool {
        guard !isSettled else { return true }
        let time = UInt64(max(time, 0))
        if state == .reaped {
            guard !name.isEmpty, let found = lineage.newestProgram(of: pid, toldUpTo: time),
                  found.program.path?.split(separator: "/").last?.hasPrefix(name) == true else { return false }
            (program, token) = (found.program, found.token)
            return true
        }
        guard let key, let found = lineage.program(key, toldUpTo: time) else { return true }
        if found.program.isKnown { program = found.program }
        token = token ?? found.token
        return true
    }
}
