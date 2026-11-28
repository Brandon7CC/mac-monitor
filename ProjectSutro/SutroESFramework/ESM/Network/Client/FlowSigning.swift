//
//  FlowSigning.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A running process's signing
/// How a running process is signed, read from the kernel with `csops_audittoken`. That takes 17 µs on macOS 13.6
/// and 2 µs on 27.2, where Security's `SecCode` takes 1.5 ms or more. The kernel checks the token's pid version, so
/// a process that exec'd or exited since its token was read answers nothing.
struct FlowSigning: Equatable {
    let signingID, teamID: String?
    let type: CodeSigningType

    /// Read a running process's signing values.
    ///
    /// - Parameters:
    ///   - token: The process's audit token.
    ///   - path: Its executable's path, for the certificates of a validly signed one.
    /// - Returns: The values, or `nil` when the process is gone or exec'd since the token was read.
    static func read(_ token: audit_token_t, path: String) -> FlowSigning? {
        var token = token, flags: UInt32 = 0
        let pid = audit_token_to_pid(token)
        guard csops_audittoken(pid, UInt32(MM_CS_OPS_STATUS), &flags, MemoryLayout<UInt32>.size, &token) == 0 else {
            return nil
        }
        return FlowSigning(signingID: identity(MM_CS_OPS_IDENTITY, pid: pid, token: &token),
                           teamID: identity(MM_CS_OPS_TEAMID, pid: pid, token: &token),
                           type: type(flags: flags, path: path))
    }

    /// How a process is signed, as a record's `codesigning_type` says. It's from its flags where they tell,
    /// as ``ProcessProgram/codesigningType(of:)`` does, else from its executable's certificates.
    ///
    /// - Parameters:
    ///   - flags: Its code signing flags, as `CS_OPS_STATUS` gives them.
    ///   - path: Its executable's path.
    ///   - certificates: The type an executable's certificates tell, read once for each file.
    /// - Returns: The type.
    static func type(flags: UInt32, path: String,
                     certificates: (String) -> CodeSigningType = { ProcessHelpers.certificateType(at: $0) })
        -> CodeSigningType {
        if flags & UInt32(CS_PLATFORM_BINARY) != 0 { return .platform }
        if flags & UInt32(CS_ADHOC) != 0 { return .adhoc }
        if flags & UInt32(CS_VALID) == 0 { return .unsigned }
        return path.isEmpty ? .unsigned : certificates(path)
    }

    /// A process's signing ID or team ID. The kernel writes an 8-byte blob header, then the text and its NUL.
    ///
    /// - Parameters:
    ///   - operation: `MM_CS_OPS_IDENTITY` or `MM_CS_OPS_TEAMID`.
    ///   - pid: The process's pid.
    ///   - token: Its audit token.
    /// - Returns: The text, or `nil` when it has none.
    private static func identity(_ operation: Int32, pid: pid_t, token: inout audit_token_t) -> String? {
        withUnsafeTemporaryAllocation(byteCount: 1_032, alignment: 8) { buffer in
            buffer.initializeMemory(as: UInt8.self, repeating: 0)
            guard csops_audittoken(pid, UInt32(operation), buffer.baseAddress, buffer.count, &token) == 0 else {
                return nil
            }
            let text = UnsafeRawBufferPointer(rebasing: buffer[8...])
            let end = text.firstIndex(of: 0) ?? text.endIndex
            return end > 0 ? String(decoding: text[..<end], as: UTF8.self) : nil
        }
    }
}
