//
//  Process.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/9/25.
//

import Foundation
import OSLog
import notify
import os


public enum CodeSigningType: String, Codable, CaseIterable {
    case platform = "PLATFORM"
    case developerId = "DEVELOPER_ID"
    case appStore = "APP_STORE"
    case adhoc = "ADHOC"
    case unsigned = "UNSIGNED"
    case unknown = "UNKNOWN"
}

public enum FileQuarantineType: String, Codable, CaseIterable {
    case optIn = "OPT_IN"
    case forced = "FORCED"
    case disabled = "DISABLED"
}


/// Models an `es_process_t`
public struct Process: Identifiable, Codable, Hashable {
    public var id = UUID.buffered()
    
    /// Time
    public var start_time: TimeVal

    /// PIDs
    public var pid: Int32 = 0
    public var ppid, original_ppid: Int32
    public var group_id, session_id: Int32
    
    /// Code signing
    public var codesigning_flags: Int64
    public var cdhash, signing_id, team_id: String?
    public var cs_validation_category: Int32?
    
    /// Audit tokens
    public var audit_token, responsible_audit_token, parent_audit_token: AuditToken?
    public var audit_token_string = "", responsible_audit_token_string = "", parent_audit_token_string = ""
    
    /// Executable
    public var executable: File?
    public var is_platform_binary, is_es_client: Bool
    
    /// TTY
    public var tty: File?
    
    /// Mac Monitor enrichment
    public var euid, ruid: Int?
    public var euid_human, ruid_human: String?
    public var codesigning_type: CodeSigningType = .unknown
    public var file_quarantine_type: FileQuarantineType = .disabled
    public var is_adhoc_signed = false
    public var cs_validation_category_string: String?
    /// The names of the flags set in ``codesigning_flags`` (``ProcessHelpers/codeSigningFlagNames(_:)``).
    public var codesigning_flag_names: [String] = []
    
    public init(from process: es_process_t, version: Int) {
        self.start_time = TimeVal(from: process.start_time)

        self.audit_token = AuditToken(from: process.audit_token)
        self.parent_audit_token = AuditToken(from: process.parent_audit_token)
        self.responsible_audit_token = AuditToken(from: process.responsible_audit_token)

        self.ppid = process.ppid
        self.original_ppid = process.original_ppid
        self.group_id = process.group_id
        self.session_id = process.session_id
        
        self.codesigning_flags = Int64(process.codesigning_flags)
        // macOS 26 support
        cs_validation_category = version >= 10 ? Int32(process.cs_validation_category.rawValue) : nil
        
        /// `nil` (eslogger's `null`) when Endpoint Security has none, and "" when it has an empty one.
        self.signing_id = process.signing_id.string
        self.team_id = process.team_id.string
        
        self.executable = File(from: process.executable.pointee)
        
        self.is_platform_binary = process.is_platform_binary
        self.is_es_client = process.is_es_client
        tty = process.tty.map { File(from: $0.pointee) }
        
        self.cdhash = ESLogger.hex(process.cdhash)
        
        derive(namingAllUsers: true)
        /// From the executable's code signing certificates, where its flags don't tell (a validly signed process that
        /// isn't a platform binary nor adhoc signed). One without a path is unsigned.
        if codesigning_type == .unknown {
            let path = executable?.path ?? ""
            codesigning_type = path.isEmpty ? .unsigned : ProcessHelpers.certificateType(at: path)
        }
        
        // MARK: File Quarantine-aware
        if let exe = self.executable {
            self.file_quarantine_type = ProcessHelpers
                .isQuarantineEnabled(forExecutableAt: exe.path, signingId: self.signing_id)
        }
    }
}


// MARK: - Mac Monitor enrichment
extension Process: ESEnrichable {
    /// Derive the pid, the user IDs, the audit token strings, what the code signing flags say (dangerous entitlements,
    /// and the code signing type where they tell it), and the code signing validation category's name.
    ///
    /// Not derived: the code signing type of a validly signed process that isn't a platform binary (it's read from the
    /// executable's certificates) and ``file_quarantine_type`` (read from the executable), which stay as they are, and
    /// the names of users other than system accounts, which stay `nil`: this Mac's user database names its own users.
    public mutating func enrich() { derive(namingAllUsers: false) }
    
    /// Derive Mac Monitor's fields from the Endpoint Security ones (see ``enrich()``).
    ///
    /// - Parameter namingAllUsers: Name every user from this Mac's user database, as the Security Extension does for
    ///   the events it records, rather than only system accounts.
    mutating func derive(namingAllUsers: Bool) {
        pid = audit_token?.pid ?? pid
        audit_token_string = audit_token?.toString() ?? audit_token_string
        parent_audit_token_string = parent_audit_token?.toString() ?? parent_audit_token_string
        responsible_audit_token_string = responsible_audit_token?.toString() ?? responsible_audit_token_string
        
        // MARK: User identification
        if let token = audit_token {
            ruid = Int(token.ruid)
            euid = Int(token.euid)
            ruid_human = Self.userName(ruid, systemAccountsOnly: !namingAllUsers)
            euid_human = euid == ruid ? ruid_human : Self.userName(euid, systemAccountsOnly: !namingAllUsers)
        }
        
        // Code Signing Blobs: Exposes Kernel/kern/cs_blobs.h header file
        func flag(_ mask: Int32) -> Bool { (Int(codesigning_flags) & Int(mask)) == Int(mask) }
        is_adhoc_signed = flag(CS_ADHOC)
        codesigning_flag_names = ProcessHelpers.codeSigningFlagNames(codesigning_flags)
        if is_platform_binary {
            codesigning_type = .platform
        } else if is_adhoc_signed {
            codesigning_type = .adhoc
        } else if !flag(CS_VALID) {
            codesigning_type = .unsigned
        }
        
        // macOS 26 support
        if let category = cs_validation_category {
            cs_validation_category_string = Self.validationCategoryNames.name(of: Int(category))
        }
    }
    
    /// Each code signing validation category's name (macOS 26 and later), as `es_cs_validation_category_t` spells it.
    static let validationCategoryNames = ConstantNames(names: Dictionary(uniqueKeysWithValues: [
        (ES_CS_VALIDATION_CATEGORY_NONE, "NONE"), (ES_CS_VALIDATION_CATEGORY_OOPJIT, "OOPJIT"),
        (ES_CS_VALIDATION_CATEGORY_INVALID, "INVALID"), (ES_CS_VALIDATION_CATEGORY_ROSETTA, "ROSETTA"),
        (ES_CS_VALIDATION_CATEGORY_PLATFORM, "PLATFORM"), (ES_CS_VALIDATION_CATEGORY_ENTERPRISE, "ENTERPRISE"),
        (ES_CS_VALIDATION_CATEGORY_TESTFLIGHT, "TESTFLIGHT"), (ES_CS_VALIDATION_CATEGORY_DEVELOPMENT, "DEVELOPMENT"),
        (ES_CS_VALIDATION_CATEGORY_APP_STORE, "APP_STORE"), (ES_CS_VALIDATION_CATEGORY_DEVELOPER_ID, "DEVELOPER_ID"),
        (ES_CS_VALIDATION_CATEGORY_LOCAL_SIGNING, "LOCAL_SIGNING"),
    ].map { (Int($0.rawValue), "ES_CS_VALIDATION_CATEGORY_" + $1) }), unknown: "UNKNOWN")
    
    /// A user's name, from this Mac's user database (``UserNames``).
    ///
    /// - Parameters:
    ///   - uid: The user's ID.
    ///   - systemAccountsOnly: Name only system accounts (IDs below 500), which every Mac shares: an event from a trace
    ///     recorded on another Mac belongs to that Mac's users, whose IDs this Mac may give to others.
    ///   - remembered: Use a name remembered from before, rather than asking the user database again.
    /// - Returns: The name, or `nil` if there's no such user (or it isn't a system account).
    static func userName(_ uid: Int?, systemAccountsOnly: Bool, remembered: Bool = true) -> String? {
        guard let uid, !systemAccountsOnly || (0..<500).contains(uid) else { return nil }
        let id = uid_t(truncatingIfNeeded: uid)
        return remembered ? UserNames.shared.name(of: id) : UserNames.databaseName(of: id)
    }
}


// MARK: - User names
/// Users' names, from this Mac's user database, remembered for a few minutes.
///
/// Every process in every event names its real and effective users. libinfo remembers only the last 20 users it looked
/// up, for the whole process, so with more users running (this Mac had 42) most lookups went to opendirectoryd and
/// back: 45 to 61 µs on an Endpoint Security thread, and about 200 µs, every time, for an ID with no user. Names are
/// kept for five minutes, and forgotten at once when Directory Services posts the notifications libinfo itself
/// forgets on (a user changed on this Mac); a change made on a directory server posts nothing, so the five minutes
/// bound how long an old name lasts. IDs with no user are kept for a few seconds. If the notifications can't be had,
/// nothing is kept.
///
/// Any thread.
final class UserNames {
    /// The one every event uses.
    static let shared = UserNames(changedBy: [kNotifyDSCacheInvalidation, kNotifyDSCacheInvalidationUser])
    /// The most IDs remembered: past this, the names start over.
    static let capacity = 1_024
    
    /// The names, and how many times the user database has changed.
    private struct State {
        var names: [uid_t: (name: String?, until: UInt64)] = [:]
        var changes = 0
        var remembers = true
    }
    
    private let state = OSAllocatedUnfairLock(initialState: State())
    /// Reads a name from the user database.
    private let lookUp: (uid_t) -> String?
    /// How long a name is remembered, in nanoseconds.
    private let hitLifetime: UInt64
    /// How long an ID with no user is remembered, in nanoseconds.
    private let missLifetime: UInt64
    /// Where the notifications arrive.
    private let queue = DispatchQueue(label: "com.swiftlydetecting.agent.UserNames")
    private var tokens: [Int32] = []
    
    /// - Parameters:
    ///   - notifications: The notifications that mean the user database changed.
    ///   - hitLifetime: How long a name is remembered, in nanoseconds: 5 minutes, since a change made on a directory
    ///     server (Active Directory, LDAP) posts nothing until Directory Services reads it again.
    ///   - missLifetime: How long an ID with no user is remembered, in nanoseconds: 10 seconds.
    ///   - lookUp: Reads a name from the user database.
    init(changedBy notifications: [String], hitLifetime: UInt64 = 300_000_000_000,
         missLifetime: UInt64 = 10_000_000_000, lookUp: @escaping (uid_t) -> String? = UserNames.databaseName(of:)) {
        self.lookUp = lookUp
        self.hitLifetime = hitLifetime
        self.missLifetime = missLifetime
        for notification in notifications {
            var token: Int32 = 0
            guard notify_register_dispatch(notification, &token, queue, { [weak self] _ in self?.forget() })
                    == NOTIFY_STATUS_OK else {
                state.withLock { $0.remembers = false }
                continue
            }
            tokens.append(token)
        }
    }
    
    deinit { tokens.forEach { notify_cancel($0) } }
    
    /// How many times the user database has changed, for tests.
    var changes: Int { state.withLock { $0.changes } }
    
    /// A user's name: remembered, or read from the user database (outside the lock) and remembered, unless the
    /// database changed meanwhile.
    ///
    /// - Parameter uid: The user's ID.
    /// - Returns: The name, or `nil` if there's no such user.
    func name(of uid: uid_t) -> String? {
        let now = DispatchTime.now().uptimeNanoseconds
        let (known, changes, remembers) = state.withLock { state in
            (state.names[uid].flatMap { $0.until > now ? $0 : nil }, state.changes, state.remembers)
        }
        if let known { return known.name }
        let name = lookUp(uid)
        guard remembers else { return name }
        state.withLock { state in
            guard state.changes == changes else { return }
            if state.names.count >= Self.capacity { state.names.removeAll(keepingCapacity: true) }
            state.names[uid] = (name, now + (name == nil ? missLifetime : hitLifetime))
        }
        return name
    }
    
    /// The user database changed: forget every name.
    func forget() {
        state.withLock { state in
            state.changes += 1
            state.names.removeAll()
        }
    }
    
    /// A user's name, read from the user database.
    ///
    /// - Parameter uid: The user's ID.
    /// - Returns: `pw_name`, or `nil` if there's no such user.
    static func databaseName(of uid: uid_t) -> String? {
        ConsoleUserSource.passwordEntry(of: uid) { $0.pw_name.map { String(cString: $0) } }
    }
}
