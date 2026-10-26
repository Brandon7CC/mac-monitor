//
//  ESXProtectDetect+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 12/30/22.
//
//

import Foundation
import CoreData

@objc(ESXProtectDetect)
public class ESXProtectDetect: NSManagedObject, Identifiable {
    @NSManaged public var signature_version: String
    @NSManaged public var malware_identifier: String
    @NSManaged public var incident_identifier: String
    @NSManaged public var detected_path: String
    @NSManaged public var detected_executable: String?

    enum CodingKeys: CodingKey {
        case signature_version
        case malware_identifier
        case incident_identifier
        case detected_path
        case detected_executable
    }
    
    // MARK: - Custom Core Data initilizer for ESXProtectDetect
    convenience init(from event: XProtectDetectEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.signature_version = event.signature_version
        self.malware_identifier = event.malware_identifier
        self.incident_identifier = event.incident_identifier
        self.detected_path = event.detected_path
        
        self.detected_executable = event.detected_executable
    }
}

// MARK: - Encodable conformance
extension ESXProtectDetect: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(signature_version, forKey: .signature_version)
        try container.encode(malware_identifier, forKey: .malware_identifier)
        try container.encode(incident_identifier, forKey: .incident_identifier)
        try container.encode(detected_path, forKey: .detected_path)
        
        try container.encode(detected_executable, forKey: .detected_executable)
    }
}
