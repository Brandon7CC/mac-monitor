//
//  Process+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/9/25.
//
//

import Foundation
import CoreData


extension ESProcess {
    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESProcess> {
        return NSFetchRequest<ESProcess>(entityName: "ESProcess")
    }

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
    // @NSManaged public var command_line: String?
}

extension ESProcess : Identifiable {

}
