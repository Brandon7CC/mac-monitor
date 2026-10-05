//
//  ESXProtectRemediate+CoreDataProperties.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 12/30/22.
//
//

import Foundation
import CoreData


extension ESXProtectRemediate {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESXProtectRemediate> {
        return NSFetchRequest<ESXProtectRemediate>(entityName: "ESXProtectRemediate")
    }

    @NSManaged public var id: UUID
    @NSManaged public var signature_version: String
    @NSManaged public var malware_identifier: String
    @NSManaged public var incident_identifier: String
    @NSManaged public var action_type: String
    @NSManaged public var success: Bool
    @NSManaged public var result_description: String
    @NSManaged public var remediated_path: String?
    @NSManaged public var remediated_process_audit_token: ESAuditToken?

}

extension ESXProtectRemediate : Identifiable {

}
