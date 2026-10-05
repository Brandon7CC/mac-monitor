//
//  AuditToken.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/16/25.
//

import Foundation

public struct AuditToken: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    public var pid, pidversion, asid: Int32
    public var auid, euid, ruid, rgid, egid: Int64
    
    public init(from token: audit_token_t) {
        self.pid = token.pid()
        self.euid = token.euid()
        self.ruid = token.ruid()
        self.rgid = token.rgid()
        self.egid = token.egid()
        self.asid = token.asid()
        self.auid = token.auid()
        self.pidversion = token.pidversion()
    }
}


public extension audit_token_t {
    /// This process's audit token (`task_info` with `TASK_AUDIT_TOKEN`), as a capture session mutes itself with.
    static var currentProcess: audit_token_t {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        _ = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        return token
    }
    
    /// Extracts the process ID (PID) from the audit token.
    func pid() -> Int32 {
        Int32(audit_token_to_pid(self))
    }

    /// Extracts the effective user ID (EUID) from the audit token.
    func euid() -> Int64 {
        Int64(audit_token_to_euid(self))
    }

    /// Extracts the real user ID (RUID) from the audit token.
    func ruid() -> Int64 {
        Int64(audit_token_to_ruid(self))
    }

    /// Extracts the real group ID (RGID) from the audit token.
    func rgid() -> Int64 {
        Int64(audit_token_to_rgid(self))
    }

    /// Extracts the effective group ID (EGID) from the audit token.
    func egid() -> Int64 {
        Int64(audit_token_to_egid(self))
    }

    /// Extracts the Audit Session ID (ASID) from the audit token.
    func asid() -> Int32 {
        Int32(audit_token_to_asid(self))
    }

    /// Extracts the Audit User ID (AUID) from the audit token
    func auid() -> Int64 {
        Int64(audit_token_to_auid(self))
    }
    
    /// Extracts the pidversion from the audit token
    func pidversion() -> Int32 {
        audit_token_to_pidversion(self)
    }

    /// Converts an audit token to a trivial string.
    func toString() -> String {
        return "pid:\(pid()), euid:\(euid()), ruid:\(ruid()), rgid:\(rgid()), egid:\(egid()), asid:\(asid()), auid:\(auid()), pidversion:\(pidversion())"
    }
}
