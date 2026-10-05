//
//  ESODEvent+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation
import CoreData


/// The stored fields every Open Directory event has (see ``OpenDirectoryEvent``).
///
/// `instigator` and `instigator_token` have to-many inverses, `ESProcess.od_instigated` and
/// `ESAuditToken.od_instigated`, which nothing reads.
extension ESODEvent {
    @NSManaged public var id: UUID?
    @NSManaged public var instigator: ESProcess?
    @NSManaged public var instigator_token: ESAuditToken?
    @NSManaged public var error_code: Int32
    @NSManaged public var node_name: String?
    @NSManaged public var db_path: String?
    
    /// Mac Monitor enrichment
    @NSManaged public var error_code_human: String?
    @NSManaged public var instigator_process_name: String?
    @NSManaged public var instigator_process_path: String?
    @NSManaged public var instigator_process_signing_id: String?
    @NSManaged public var instigator_process_audit_token: String?
}
