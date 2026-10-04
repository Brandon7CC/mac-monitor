//
//  ESGatekeeperUserOverrideEvent+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/18/25.
//
//

public import CoreData


@objc(ESGatekeeperUserOverrideEvent)
public class ESGatekeeperUserOverrideEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case file_type
        case file_type_string
        case file
        case file_path
        case sha256
        /// For some reason ESLogger as of macOS 26 does not emit this object...
        case signing_info
    }
    
    // MARK: - Custom Core Data initilizer for ESGatekeeperUserOverrideEvent
    convenience init(
        from message: Message,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        let override: GatekeeperUserOverrideEvent = message.event.gatekeeper_user_override!
        let description = NSEntityDescription.entity(forEntityName: "ESGatekeeperUserOverrideEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = UUID()
        
        file_type = override.file_type
        file_type_string = override.file_type_string
        
        /// We need to report the file union differently to the app to conform to ESLogger's oddness...
        if let file = override.file.file {
            attach(ESFile.row(for: file, in: context), to: #keyPath(ESGatekeeperUserOverrideEvent.file))
        }
        if let file_path = override.file.file_path {
            self.file_path = file_path
        }
        
        /// ESLogger for some reason reports when this is null as a string...
        /// `"sha256": "NULL"`
        sha256 = override.sha256 ?? "NULL"
        
        /// For some reason ESLogger as of macOS 26 does not emit this object...
        if let signing_info = override.signing_info {
            self.signing_info = ESSignedFileInfo(
                from: signing_info,
                insertIntoManagedObjectContext: context
            )
        }
    }
}

// MARK: - Encodable conformance and helper
extension ESGatekeeperUserOverrideEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        //        try container.encode(id, forKey: .id)
        try container.encode(file_type, forKey: .file_type)
        try container.encode(file_type_string, forKey: .file_type_string)
        try container.encodeIfPresent(file, forKey: .file)
        try container.encodeIfPresent(file_path, forKey: .file_path)
        try container.encode(sha256, forKey: .sha256)
        try container.encode(signing_info, forKey: .signing_info)
    }
}
