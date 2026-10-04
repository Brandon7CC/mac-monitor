//
//  ESXProtectRemediate+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 12/30/22.
//
//

import Foundation
import CoreData

@objc(ESXProtectRemediate)
public class ESXProtectRemediate: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case signature_version
        case malware_identifier
        case incident_identifier
        case action_type
        case success
        case result_description
        case remediated_path
        case remediated_process_audit_token
    }
    
    // MARK: - Custom Core Data initilizer for ESXProtectRemediate
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let xprotectRemediateItem: XProtecRemediateEvent = message.event.xp_malware_remediated!
        let description = NSEntityDescription.entity(forEntityName: "ESXProtectRemediate", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = xprotectRemediateItem.id
        
        self.signature_version = xprotectRemediateItem.signature_version
        self.malware_identifier = xprotectRemediateItem.malware_identifier
        self.incident_identifier = xprotectRemediateItem.incident_identifier
        self.action_type = xprotectRemediateItem.action_type
        self.success = xprotectRemediateItem.success
        self.result_description = xprotectRemediateItem.result_description
        self.remediated_path = xprotectRemediateItem.remediated_path
        if let token = xprotectRemediateItem.remediated_process_audit_token {
            self.remediated_process_audit_token = ESAuditToken(from: token, insertIntoManagedObjectContext: context)
        }
    }
}

// MARK: - Encodable conformance
extension ESXProtectRemediate: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(id, forKey: .id)
        try container.encode(signature_version, forKey: .signature_version)
        try container.encode(malware_identifier, forKey: .malware_identifier)
        try container.encode(incident_identifier, forKey: .incident_identifier)
        try container.encode(action_type, forKey: .action_type)
        try container.encode(success, forKey: .success)
        try container.encode(result_description, forKey: .result_description)
        try container.encode(remediated_path, forKey: .remediated_path)
        try container.encode(remediated_process_audit_token, forKey: .remediated_process_audit_token)
    }
}
