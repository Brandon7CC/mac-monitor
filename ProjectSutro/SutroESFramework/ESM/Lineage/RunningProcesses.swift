//
//  RunningProcesses.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation
import Security


// MARK: - Running processes
/// The processes running now, as ``ProcessLineage`` is seeded with them: each one's key, parent, executable, command
/// line and signature, read from the system as root (Security Extension context).
///
/// Reading every process's key, parent, path and arguments took 6 ms for 685 processes on macOS 27.2. A signature
/// is a few milliseconds each, so the whole list is read off any queue that events wait on.
enum RunningProcesses {
    /// Read every running process but the kernel and launchd.
    ///
    /// - Parameter signatures: Read each one's signature too?
    /// - Returns: Each process's program and its parent's pid. A process that exited meanwhile, or whose pid
    ///   version can't be read, is left out.
    static func read(signatures: Bool = true) -> [(program: ProcessProgram, parent: Int32)] {
        var pids = [pid_t](repeating: 0, count: Int(proc_listallpids(nil, 0)) + 128)
        let listed = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size)))
        return pids.prefix(max(listed, 0)).compactMap { process($0, signature: signatures) }
    }

    /// Read one running process.
    ///
    /// - Parameters:
    ///   - pid: Its pid.
    ///   - signature: Read its signature too? A few milliseconds, where the rest is microseconds.
    /// - Returns: Its program and its parent's pid, or `nil` for the kernel, launchd, a process that's gone, and
    ///   one whose pid version can't be read.
    static func process(_ pid: pid_t, signature: Bool) -> (program: ProcessProgram, parent: Int32)? {
        guard pid > ProcessKey.launchd, let token = token(of: pid) else { return nil }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        let signed = signature ? self.signature(of: token) : nil
        let program = ProcessProgram(key: ProcessKey(token),
                                     path: ProcessPath.live(pid, AuditToken(from: token)) ?? "",
                                     commandLine: arguments(of: pid).map(ProcessProgram.commandLine),
                                     signingID: signed?.signingID, teamID: signed?.teamID,
                                     codesigningType: signed?.type.rawValue)
        return (program, Int32(bitPattern: info.pbi_ppid))
    }

    /// A running process's audit token, which has its pid version.
    ///
    /// - Parameter pid: The process's pid.
    /// - Returns: The token, or `nil` when the process is gone or its task can't be named.
    static func token(of pid: pid_t) -> audit_token_t? {
        var name = mach_port_name_t(MACH_PORT_NULL)
        guard task_name_for_pid(mach_task_self_, pid, &name) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, name) }
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(name, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? token : nil
    }

    /// A running process's arguments (`sysctl` with `KERN_PROCARGS2`).
    ///
    /// - Parameter pid: The process's pid.
    /// - Returns: The arguments, or `nil` when they can't be read.
    static func arguments(of pid: pid_t) -> [String]? {
        var name: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&name, 3, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&name, 3, &buffer, &size, nil, 0) == 0 else { return nil }
        return arguments(in: buffer.prefix(size))
    }

    /// The arguments in what `KERN_PROCARGS2` returns: a count, the executable's path, padding, then each argument
    /// and environment variable, each ended by a NUL.
    ///
    /// - Parameter bytes: What the kernel returned.
    /// - Returns: The arguments, or `nil` when the bytes are too short to hold the count.
    static func arguments(in bytes: some RandomAccessCollection<UInt8>) -> [String]? {
        let bytes = Array(bytes)
        guard bytes.count > MemoryLayout<Int32>.size else { return nil }
        let count = bytes.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        var index = MemoryLayout<Int32>.size
        while index < bytes.count, bytes[index] != 0 { index += 1 }
        while index < bytes.count, bytes[index] == 0 { index += 1 }
        var arguments: [String] = []
        while arguments.count < Int(count), index < bytes.count {
            let end = bytes[index...].firstIndex(of: 0) ?? bytes.count
            arguments.append(String(decoding: bytes[index..<end], as: UTF8.self))
            index = end + 1
        }
        return arguments
    }

    /// A running process's signature, read from the code it runs without validating it.
    ///
    /// - Parameter token: The process's audit token.
    /// - Returns: The signature, or `nil` when Security can't find the process's code.
    static func signature(of token: audit_token_t) -> StaticCodeSigning? {
        var token = token
        let audit = Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)
        var code: SecCode?, staticCode: SecStaticCode?, information: CFDictionary?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: audit] as CFDictionary, [], &code)
                == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        let status = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation),
                                                   &information)
        guard status == errSecSuccess || status == errSecCSUnsigned else { return nil }
        return StaticCodeSigning(information: information as? [String: Any] ?? [:])
    }
}
