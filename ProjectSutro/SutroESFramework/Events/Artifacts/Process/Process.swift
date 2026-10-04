//
//  Process.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/9/25.
//

import Foundation
import OSLog


public enum CodeSigningType: String, Codable {
    case platform = "PLATFORM"
    case developerId = "DEVELOPER_ID"
    case appStore = "APP_STORE"
    case adhoc = "ADHOC"
    case unsigned = "UNSIGNED"
    case unknown = "UNKNOWN"
}

public enum FileQuarantineType: String, Codable {
    case optIn = "OPT_IN"
    case forced = "FORCED"
    case disabled = "DISABLED"
}


/// Models an `es_process_t`
/// Ensure Process conforms to Codable and Equatable
public struct Process: Identifiable, Codable, Hashable {
    public var id = UUID()
    
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
    // public var command_line: String?
    // Inc. dangerous entitlements
    public var is_adhoc_signed = false, get_task_allow = false, allow_jit = false, rootless = false, skip_lv = false
    public var cs_validation_category_string: String?
    
    public init(from process: es_process_t, version: Int, isExecMessage: Bool = false) {
        self.start_time = TimeVal(from: process.start_time)

        self.audit_token = AuditToken(from: process.audit_token)
        self.parent_audit_token = AuditToken(from: process.parent_audit_token)
        self.responsible_audit_token = AuditToken(
            from: process.responsible_audit_token
        )

        self.ppid = process.ppid
        self.original_ppid = process.original_ppid
        self.group_id = process.group_id
        self.session_id = process.session_id
        
        self.codesigning_flags = Int64(process.codesigning_flags)
        // macOS 26 support
        if version >= 10 {
            self.cs_validation_category = Int32(process.cs_validation_category.rawValue)
        }
        
        if process.signing_id.length > 0 {
            self.signing_id = String(cString: process.signing_id.data)
        }
        if process.team_id.length > 0 {
            self.team_id = String(cString: process.team_id.data)
        }
        
        self.executable = File(from: process.executable.pointee)
        
        self.is_platform_binary = process.is_platform_binary
        self.is_es_client = process.is_es_client

        if let ttyPointer = process.tty {
            self.tty = File(from: ttyPointer.pointee)
        }
        
        self.cdhash = cdhashToString(cdhash: process.cdhash)
        
        derive(namingAllUsers: true)
        /// From the executable's code signing certificates, where its flags don't tell.
        self.codesigning_type = ProcessHelpers.codeSigningType(for: process)
        
        // MARK: File Quarantine-aware
        if let exe = self.executable {
            self.file_quarantine_type = ProcessHelpers
                .isQuarantineEnabled(forExecutableAt: exe.path, signingId: self.signing_id)
        } else {
            self.file_quarantine_type = .disabled
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
            euid_human = Self.userName(euid, systemAccountsOnly: !namingAllUsers)
        }
        
        // Code Signing Blobs: Exposes Kernel/kern/cs_blobs.h header file
        func flag(_ mask: Int32) -> Bool { (Int(codesigning_flags) & Int(mask)) == Int(mask) }
        is_adhoc_signed = flag(CS_ADHOC)
        get_task_allow = flag(CS_GET_TASK_ALLOW)
        //` com.apple.security.cs.allow-jit`
        allow_jit = flag(CS_EXECSEG_JIT)
        // `com.apple.rootless.restricted-nvram-variables.heritable entitlement`
        rootless = flag(CS_NVRAM_UNRESTRICTED)
        // Skip library validation
        skip_lv = flag(CS_EXECSEG_SKIP_LV)
        if is_platform_binary {
            codesigning_type = .platform
        } else if is_adhoc_signed {
            codesigning_type = .adhoc
        } else if !flag(CS_VALID) {
            codesigning_type = .unsigned
        }
        
        // macOS 26 support
        if let category = cs_validation_category {
            switch es_cs_validation_category_t(rawValue: UInt32(truncatingIfNeeded: category)) {
            case ES_CS_VALIDATION_CATEGORY_NONE:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_NONE"
            case ES_CS_VALIDATION_CATEGORY_OOPJIT:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_OOPJIT"
            case ES_CS_VALIDATION_CATEGORY_INVALID:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_INVALID"
            case ES_CS_VALIDATION_CATEGORY_ROSETTA:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_ROSETTA"
            case ES_CS_VALIDATION_CATEGORY_PLATFORM:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_PLATFORM"
            case ES_CS_VALIDATION_CATEGORY_ENTERPRISE:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_ENTERPRISE"
            case ES_CS_VALIDATION_CATEGORY_TESTFLIGHT:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_TESTFLIGHT"
            case ES_CS_VALIDATION_CATEGORY_DEVELOPMENT:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_TESTFLIGHT"
            case ES_CS_VALIDATION_CATEGORY_APP_STORE:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_APP_STORE"
            case ES_CS_VALIDATION_CATEGORY_DEVELOPER_ID:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_DEVELOPER_ID"
            case ES_CS_VALIDATION_CATEGORY_LOCAL_SIGNING:
                self.cs_validation_category_string = "ES_CS_VALIDATION_CATEGORY_LOCAL_SIGNING"
            default:
                self.cs_validation_category_string = "UNKNOWN"
            }
        }
    }
    
    /// A user's name, from this Mac's user database.
    ///
    /// - Parameters:
    ///   - uid: The user's ID.
    ///   - systemAccountsOnly: Name only system accounts (IDs below 500), which every Mac shares: an event from a trace
    ///     recorded on another Mac belongs to that Mac's users, whose IDs this Mac may give to others.
    /// - Returns: The name, or `nil` if there's no such user (or it isn't a system account).
    static func userName(_ uid: Int?, systemAccountsOnly: Bool) -> String? {
        guard let uid, !systemAccountsOnly || (0..<500).contains(uid),
              let entry = getpwuid(uid_t(truncatingIfNeeded: uid)) else { return nil }
        return String(cString: entry.pointee.pw_name)
    }
}
