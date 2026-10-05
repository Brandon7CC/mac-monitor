//
//  AuditToken+Values.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Tokens from values
extension AuditToken {
    /// A token from its eight values (a decoded trace, a LaunchServices record), with the zeroed `id` row cache keys
    /// have (``rowKey``), so equal tokens compare equal.
    ///
    /// - Parameters:
    ///   - pid: The process ID.
    ///   - pidversion: The pid version, which tells a reused pid apart.
    ///   - asid: The audit session ID.
    ///   - auid: The audit user ID.
    ///   - euid: The effective user ID.
    ///   - ruid: The real user ID.
    ///   - rgid: The real group ID.
    ///   - egid: The effective group ID.
    init(pid: Int32, pidversion: Int32, asid: Int32, auid: Int64, euid: Int64, ruid: Int64, rgid: Int64, egid: Int64) {
        self.pid = pid
        self.pidversion = pidversion
        self.asid = asid
        self.auid = auid
        self.euid = euid
        self.ruid = ruid
        self.rgid = rgid
        self.egid = egid
        self.id = zeroID
    }
    
    /// Does this token name the same process image as another, whatever their `id`s?
    ///
    /// - Parameter other: Another token.
    /// - Returns: `true` when both the pid and the pid version match.
    func isSameProcess(as other: AuditToken) -> Bool {
        pid == other.pid && pidversion == other.pidversion
    }
}


// MARK: - eslogger's shape
/// An audit token as eslogger writes one: its eight values, without Mac Monitor's `id`.
///
/// Mac Monitor's own ``AuditToken`` encodes its random `id` too. Mac Monitor's additions write tokens this way, and
/// read either shape (an `id` is ignored).
struct ESLoggerAuditToken: Codable {
    let pid, pidversion, asid: Int32
    let auid, euid, ruid, rgid, egid: Int64
    
    /// - Parameter token: The token to write.
    init(_ token: AuditToken) {
        (pid, pidversion, asid) = (token.pid, token.pidversion, token.asid)
        (auid, euid, ruid, rgid, egid) = (token.auid, token.euid, token.ruid, token.rgid, token.egid)
    }
    
    /// The token, with a zeroed `id`.
    var token: AuditToken {
        AuditToken(pid: pid, pidversion: pidversion, asid: asid, auid: auid, euid: euid, ruid: ruid, rgid: rgid,
                   egid: egid)
    }
}
