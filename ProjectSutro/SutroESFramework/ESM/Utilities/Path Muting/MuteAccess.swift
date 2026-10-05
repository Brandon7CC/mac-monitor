//
//  MuteAccess.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation
import Darwin.membership


// MARK: - Access
/// What a caller may do with the saved mute set, as the Security Extension decides it for each request.
///
/// Every reply says which (``MuteReply/access``), so Mac Monitor can disable what it may not do and say why.
public enum MuteAccess: String, Codable, Sendable {
    /// List it, but not change it: another Mac Monitor owns the event stream.
    case read
    /// List and change it.
    case write
    /// List it, but never change it: the user running Mac Monitor isn't an administrator.
    case standardUser
    
    /// What a Mac Monitor connection may do. Only an administrator's Mac Monitor may change the saved set, and like
    /// installing an update, only while it owns the event stream or nobody does. Anyone may list it.
    ///
    /// - Parameters:
    ///   - isAdministrator: Is the connection's effective user an administrator (``AdministratorCheck``)?
    ///   - controlsStream: Does the connection own the event stream, or does nobody?
    /// - Returns: ``standardUser`` for anyone but an administrator, else ``write`` or ``read``.
    public static func app(isAdministrator: Bool, controlsStream: Bool) -> MuteAccess {
        guard isAdministrator else { return .standardUser }
        return controlsStream ? .write : .read
    }
    
    /// Why a change is refused, as the reply's status and a sentence for Mac Monitor to show.
    public var refusal: (status: MuteReply.Status, problem: String)? {
        switch self {
        case .write:
            return nil
        case .read:
            return (.refused, "Only the Mac Monitor that owns the event stream can change the saved mute set.")
        case .standardUser:
            return (.notAdministrator, """
                Only an administrator can change the saved mute set. You can still view it, export it, and record \
                with it.
                """)
        }
    }
}


// MARK: - Administrators
/// Decides whether a user is an administrator: a member of the `admin` group. Only an administrator's Mac Monitor may
/// change the saved mute set; `macmonitor` runs as root.
///
/// The Security Extension asks about the effective user the kernel recorded for a connection, on every request about
/// the saved set. Tests pass their own answer, so they need no real accounts.
public struct AdministratorCheck: Sendable {
    /// The `admin` group's ID.
    public static let adminGroup: gid_t = 80
    
    /// Answers for one user ID.
    private let answer: @Sendable (uid_t) -> Bool
    
    /// - Parameter answer: Is a user ID an administrator's?
    public init(_ answer: @escaping @Sendable (uid_t) -> Bool) {
        self.answer = answer
    }
    
    /// Is a user an administrator?
    ///
    /// - Parameter uid: The user ID.
    /// - Returns: `true` for a member of the `admin` group.
    public func isAdministrator(_ uid: uid_t) -> Bool {
        answer(uid)
    }
    
    /// Is the user behind a connection an administrator? Only the effective user the kernel recorded for it when it
    /// connected counts, never its process ID. No connection means no user to vouch for, so nothing may change.
    ///
    /// - Parameter caller: The connection a request arrived on (`NSXPCConnection.current()`), if any.
    /// - Returns: `true` only for a connection whose effective user is an administrator.
    public func isAdministrator(_ caller: (any PeerConnection)?) -> Bool {
        caller.map { isAdministrator($0.effectiveUserIdentifier) } ?? false
    }
    
    /// Open Directory's answer (`mbr_check_membership`), which counts nested groups, as the system's own
    /// administrator checks do. A user or group it can't resolve, or a check that fails, isn't an administrator.
    public static let openDirectory = AdministratorCheck { uid in
        isMember(uid, of: adminGroup)
    }
    
    /// Ask Open Directory whether a user is a member of a group.
    ///
    /// - Parameters:
    ///   - uid: The user ID.
    ///   - gid: The group ID.
    /// - Returns: `true` only if Open Directory says the user is a member.
    static func isMember(_ uid: uid_t, of gid: gid_t) -> Bool {
        var user = [UInt8](repeating: 0, count: 16), group = [UInt8](repeating: 0, count: 16)
        guard mbr_uid_to_uuid(uid, &user) == 0, mbr_gid_to_uuid(gid, &group) == 0 else { return false }
        var isMember: Int32 = 0
        return mbr_check_membership(user, group, &isMember) == 0 && isMember != 0
    }
}
