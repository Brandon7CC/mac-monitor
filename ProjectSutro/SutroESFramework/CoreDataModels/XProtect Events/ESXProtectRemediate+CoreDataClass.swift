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
public class ESXProtectRemediate: NSManagedObject, Identifiable {
    @NSManaged public var signature_version: String
    @NSManaged public var malware_identifier: String
    @NSManaged public var incident_identifier: String
    @NSManaged public var action_type: String
    @NSManaged public var success: Bool
    @NSManaged public var result_description: String
    @NSManaged public var remediated_path: String?
    @NSManaged public var remediated_process_audit_token: ESAuditToken?

    enum CodingKeys: CodingKey {
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
    convenience init(from event: XProtecRemediateEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.signature_version = event.signature_version
        self.malware_identifier = event.malware_identifier
        self.incident_identifier = event.incident_identifier
        self.action_type = event.action_type
        self.success = event.success
        self.result_description = event.result_description
        self.remediated_path = event.remediated_path
        if let token = event.remediated_process_audit_token {
            self.remediated_process_audit_token = ESAuditToken(from: token, insertIntoManagedObjectContext: context)
        }
    }
}

// MARK: - Encodable conformance
extension ESXProtectRemediate: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
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
