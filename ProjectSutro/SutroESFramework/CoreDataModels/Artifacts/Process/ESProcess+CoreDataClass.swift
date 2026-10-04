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
public class ESProcess: NSManagedObject {
    convenience init(
        from process: Process,
        version: Int,
        insertIntoManagedObjectContext context: NSManagedObjectContext
    ) {
        let description = NSEntityDescription.entity(forEntityName: "ESProcess", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = process.id
        
        /// Time
        self.start_time = process.start_time.humanFormat()
        
        /// PIDs
        self.pid = process.pid
        self.ppid = process.ppid
        self.original_ppid = process.original_ppid
        self.group_id = process.group_id
        self.session_id = process.session_id
        
        /// Audit tokens: rows shared with every process that has the same token (see ``EventRowCaches``). The strings are
        /// formatted from the values, as reading a shared row would load it.
        if let audit_token = process.audit_token {
            attach(ESAuditToken.row(for: audit_token, in: context), to: #keyPath(ESProcess.audit_token))
            self.audit_token_string = audit_token.toString()
        }
        
        if let parent_audit_token = process.parent_audit_token {
            attach(ESAuditToken.row(for: parent_audit_token, in: context), to: #keyPath(ESProcess.parent_audit_token))
            self.parent_audit_token_string = parent_audit_token.toString()
        }
        
        if let responsible_audit_token = process.responsible_audit_token {
            attach(ESAuditToken.row(for: responsible_audit_token, in: context), to: #keyPath(ESProcess.responsible_audit_token))
            self.responsible_audit_token_string = responsible_audit_token.toString()
        }
        
        /// Codesigning
        self.codesigning_flags = process.codesigning_flags
        if let signing_id = process.signing_id {
            self.signing_id = signing_id
        }
        if let team_id = process.team_id {
            self.team_id = team_id
        }
        if let cdhash = process.cdhash {
            self.cdhash = cdhash
        }
        
        self.is_adhoc_signed = process.is_adhoc_signed
        
        // macOS 26
        if version >= 10 {
            if let cs_validation_category = process.cs_validation_category,
               let cs_validation_category_string = process.cs_validation_category_string {
                self.cs_validation_category = cs_validation_category
                self.cs_validation_category_string = cs_validation_category_string
            }
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
        if let euid = process.euid {
            self.euid = Int64(euid)
        }
        if let euid_human = process.euid_human {
            self.euid_human = euid_human
        }
        
        if let ruid = process.ruid {
            self.ruid = Int64(ruid)
        }
        if let ruid_human = process.ruid_human {
            self.ruid_human = ruid_human
        }
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
        try container.encodeIfPresent(signing_id, forKey: .signing_id)
        try container.encode(team_id, forKey: .team_id)
        try container.encodeIfPresent(cdhash, forKey: .cdhash)
        try container.encode(is_adhoc_signed, forKey: .is_adhoc_signed)
        
        if #available(macOS 14.0, *) {
            try container.encode(cs_validation_category, forKey: .cs_validation_category)
            try container.encodeIfPresent(cs_validation_category_string, forKey: .cs_validation_category_string)
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
