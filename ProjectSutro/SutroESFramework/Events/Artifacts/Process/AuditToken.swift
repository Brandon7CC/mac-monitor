//
//  AuditToken.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/16/25.
//

import Foundation

public struct AuditToken: Identifiable, Codable, Hashable {
    public var id = UUID.buffered()
    
    public var pid, pidversion, asid: Int32
    public var auid, euid, ruid, rgid, egid: Int64
    
    public init(from token: audit_token_t) {
        self.pid = audit_token_to_pid(token)
        self.euid = Int64(audit_token_to_euid(token))
        self.ruid = Int64(audit_token_to_ruid(token))
        self.rgid = Int64(audit_token_to_rgid(token))
        self.egid = Int64(audit_token_to_egid(token))
        self.asid = audit_token_to_asid(token)
        self.auid = Int64(audit_token_to_auid(token))
        self.pidversion = audit_token_to_pidversion(token)
    }

    /// The token as the kernel takes one, such as `proc_pidpath_audittoken`, which checks its pid and pid version.
    var raw: audit_token_t {
        let ids = [auid, euid, egid, ruid, rgid].map { UInt32(truncatingIfNeeded: $0) }
        return audit_token_t(val: (ids[0], ids[1], ids[2], ids[3], ids[4], UInt32(bitPattern: pid),
                                   UInt32(bitPattern: asid), UInt32(bitPattern: pidversion)))
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
}
