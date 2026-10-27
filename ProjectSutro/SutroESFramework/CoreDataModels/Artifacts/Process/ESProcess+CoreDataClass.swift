//
//  Process+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/9/25.
//
//

import Foundation
import CoreData

@objc(ESProcess)
public class ESProcess: NSManagedObject, Identifiable {
    @NSManaged public var id: UUID?
    
    /// TIme
    @NSManaged public var start_time: String
    
    /// PIDs
    @NSManaged public var pid: Int32
    @NSManaged public var ppid: Int32
    @NSManaged public var original_ppid: Int32
    @NSManaged public var group_id: Int32
    @NSManaged public var session_id: Int32
    
    /// Audit tokens
    @NSManaged public var audit_token: ESAuditToken?
    @NSManaged public var responsible_audit_token: ESAuditToken?
    @NSManaged public var parent_audit_token: ESAuditToken?
    @NSManaged public var audit_token_string: String
    @NSManaged public var responsible_audit_token_string: String
    @NSManaged public var parent_audit_token_string: String
    
    /// Codesigning
    @NSManaged public var codesigning_flags: Int64
    @NSManaged public var cdhash: String?
    @NSManaged public var signing_id: String?
    @NSManaged public var team_id: String?
    @NSManaged public var cs_validation_category: Int32
    @NSManaged public var cs_validation_category_string: String?
    
    @NSManaged public var is_platform_binary: Bool
    @NSManaged public var is_es_client: Bool
    
    @NSManaged public var executable: ESFile?
    @NSManaged public var tty: ESFile?
    
    // MARK: - Enrichment
    @NSManaged public var euid: Int64
    @NSManaged public var ruid: Int64
    @NSManaged public var euid_human: String?
    @NSManaged public var ruid_human: String?
    @NSManaged public var codesigning_type: String
    @NSManaged public var is_adhoc_signed: Bool
    @NSManaged public var file_quarantine_type: String

    convenience init(
        from process: Process,
        version: Int,
        insertIntoManagedObjectContext context: NSManagedObjectContext
    ) {
        self.init(insertingInto: context)
        self.id = process.id
        
        /// Time
        self.start_time = process.start_time.humanFormat()
        
        /// PIDs
        self.pid = process.pid
        self.ppid = process.ppid
        self.original_ppid = process.original_ppid
        self.group_id = process.group_id
        self.session_id = process.session_id
        
        /// Audit tokens: rows shared with every process that has the same token (see ``EventRowCaches``). The strings
        /// are formatted from the values, as reading a shared row would load it.
        if let audit_token = process.audit_token {
            attach(ESAuditToken.row(for: audit_token, in: context), to: #keyPath(ESProcess.audit_token))
            self.audit_token_string = audit_token.toString()
        }
        
        if let parent_audit_token = process.parent_audit_token {
            attach(ESAuditToken.row(for: parent_audit_token, in: context), to: #keyPath(ESProcess.parent_audit_token))
            self.parent_audit_token_string = parent_audit_token.toString()
        }
        
        if let responsible_audit_token = process.responsible_audit_token {
            attach(ESAuditToken.row(for: responsible_audit_token, in: context),
                   to: #keyPath(ESProcess.responsible_audit_token))
            self.responsible_audit_token_string = responsible_audit_token.toString()
        }
        
        /// Codesigning
        self.codesigning_flags = process.codesigning_flags
        self.signing_id = process.signing_id
        self.team_id = process.team_id
        /// Uppercase like eslogger, also when an older Security Extension sent lowercase.
        self.cdhash = process.cdhash?.uppercased()
        
        self.is_adhoc_signed = process.is_adhoc_signed
        
        // macOS 26
        if version >= 10, let cs_validation_category = process.cs_validation_category,
           let cs_validation_category_string = process.cs_validation_category_string {
            self.cs_validation_category = cs_validation_category
            self.cs_validation_category_string = cs_validation_category_string
        }
        
        self.is_platform_binary = process.is_platform_binary
        self.is_es_client = process.is_es_client
        
        if let exe = process.executable {
            /// Executable
            attach(ESFile.row(for: exe, in: context), to: #keyPath(ESProcess.executable))
            /// @note Enrichment - File Quarantine
            self.file_quarantine_type = process.file_quarantine_type.rawValue
            /// @note Enrichment - Codesigning type
            self.codesigning_type = process.codesigning_type.rawValue
        }
        
        /// TTY
        if let tty = process.tty {
            attach(ESFile.row(for: tty, in: context), to: #keyPath(ESProcess.tty))
        }
        
        /// User identification
        self.euid = Int64(process.euid ?? 0)
        self.euid_human = process.euid_human
        self.ruid = Int64(process.ruid ?? 0)
        self.ruid_human = process.ruid_human
    }
    
    /// The row for `process`: shared with every other event (and `EXEC` target or `FORK` child) of the same process
    /// when `context` has ``EventRowCaches``, or a new row otherwise.
    ///
    /// A shared row keeps the `id` of the first process stored in it, so whoever attaches it keeps their own `id` to
    /// export (``ESMessage/process_id``, ``ESProcessExecEvent/target_id``, ``ESProcessForkEvent/child_id``).
    ///
    /// - Parameters:
    ///   - process: The process.
    ///   - version: The message's version.
    ///   - context: The context to insert into.
    /// - Returns: The row, which may be a fault: attach it with ``NSManagedObject/attach(_:to:)``.
    static func row(for process: Process, version: Int, in context: NSManagedObjectContext) -> ESProcess {
        EventRowCaches.row(\.processes, for: ProcessRowKey(version: version, process: process.rowKey), in: context) {
            ESProcess(from: process, version: version, insertIntoManagedObjectContext: context)
        }
    }
    
    /// A new row for `process`, owned by the event that stores it, or `nil` without one.
    ///
    /// - Parameters:
    ///   - process: The process, or `nil` when Endpoint Security left it out.
    ///   - version: The message's version.
    ///   - context: The context to insert into.
    /// - Returns: The new row, or `nil`.
    static func insert(_ process: Process?, version: Int, in context: NSManagedObjectContext) -> ESProcess? {
        process.map { ESProcess(from: $0, version: version, insertIntoManagedObjectContext: context) }
    }
}

/// An ``ESProcess`` encoded with the `id` of the process it stands for, which a shared row doesn't have.
struct ESProcessRecord: Encodable {
    let process: ESProcess
    let id: UUID?
    
    func encode(to encoder: Encoder) throws {
        try process.encode(to: encoder, id: id)
    }
}

// MARK: - Encodable conformance
extension ESProcess: Encodable {
    enum CodingKeys: String, CodingKey {
        case id, start_time, pid, ppid, original_ppid, group_id, session_id, audit_token, audit_token_string, parent_audit_token, parent_audit_token_string, responsible_audit_token, responsible_audit_token_string, codesigning_flags, cdhash, signing_id, team_id, is_adhoc_signed, is_platform_binary, is_es_client, cs_validation_category, cs_validation_category_string, executable, file_quarantine_type, codesigning_type, tty, euid, euid_human, ruid, ruid_human
        case codesigning_flag_names
    }
    
    public func encode(to encoder: Encoder) throws {
        try encode(to: encoder, id: id)
    }
    
    /// Encode this process as the one with `id`.
    ///
    /// - Parameters:
    ///   - encoder: The encoder.
    ///   - id: The `id` to encode: the event's own, for a shared row.
    func encode(to encoder: Encoder, id: UUID?) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(id, forKey: .id)
        try container.encode(start_time, forKey: .start_time)
        
        try container.encode(pid, forKey: .pid)
        try container.encode(ppid, forKey: .ppid)
        try container.encode(original_ppid, forKey: .original_ppid)
        try container.encode(group_id, forKey: .group_id)
        try container.encode(session_id, forKey: .session_id)
        
        try container.encodeIfPresent(audit_token, forKey: .audit_token)
        try container.encodeIfPresent(audit_token_string, forKey: .audit_token_string)
        try container.encodeIfPresent(parent_audit_token, forKey: .parent_audit_token)
        try container.encodeIfPresent(parent_audit_token_string, forKey: .parent_audit_token_string)
        try container.encodeIfPresent(responsible_audit_token, forKey: .responsible_audit_token)
        try container.encodeIfPresent(responsible_audit_token_string, forKey: .responsible_audit_token_string)
        
        try container.encode(codesigning_flags, forKey: .codesigning_flags)
        try container.encode(signing_id, forKey: .signing_id)
        try container.encode(team_id, forKey: .team_id)
        try container.encodeIfPresent(cdhash, forKey: .cdhash)
        try container.encode(is_adhoc_signed, forKey: .is_adhoc_signed)
        /// Derived when written, from the flags: not stored.
        try container.encode(ProcessHelpers.codeSigningFlagNames(codesigning_flags), forKey: .codesigning_flag_names)
        
        /// Endpoint Security's from message version 10 (`ESMessageCore.h`), and stored with its name only then: before
        /// it eslogger writes no category, and the attribute's default (0) would read as
        /// `ES_CS_VALIDATION_CATEGORY_INVALID`.
        if let cs_validation_category_string {
            try container.encode(cs_validation_category, forKey: .cs_validation_category)
            try container.encode(cs_validation_category_string, forKey: .cs_validation_category_string)
        }
        
        try container.encode(is_es_client, forKey: .is_es_client)
        try container.encode(is_platform_binary, forKey: .is_platform_binary)
        
        try container.encodeIfPresent(executable, forKey: .executable)
        try container.encodeIfPresent(file_quarantine_type, forKey: .file_quarantine_type)
        try container.encodeIfPresent(codesigning_type, forKey: .codesigning_type)
        
        try container.encode(tty, forKey: .tty)
        
        try container.encode(euid, forKey: .euid)
        try container.encode(ruid, forKey: .ruid)
        try container.encodeIfPresent(euid_human, forKey: .euid_human)
        try container.encodeIfPresent(ruid_human, forKey: .ruid_human)
    }
}


// MARK: - Code signing flags
extension ESProcess {
    /// The names of the flags set in ``codesigning_flags`` (``ProcessHelpers/codeSigningFlagNames(_:)``).
    public var codesigningFlagNames: [String] {
        ProcessHelpers.codeSigningFlagNames(codesigning_flags)
    }

    /// Is the process adhoc signed by the linker, as a freshly compiled binary is?
    public var isLinkerSignedAdhoc: Bool {
        let names = codesigningFlagNames
        return names.contains("CS_ADHOC") && names.contains("CS_LINKER_SIGNED")
    }
}
