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
        
        /// The union's arm: a file, or a path. An unknown arm stores neither.
        if let file = override.file.file {
            attach(ESFile.row(for: file, in: context), to: #keyPath(ESGatekeeperUserOverrideEvent.file))
        }
        if let file_path = override.file.file_path {
            self.file_path = file_path
        }
        
        /// ESLogger for some reason reports when this is null as a string...
        /// `"sha256": "NULL"`
        /// Uppercase like eslogger, also when an older Security Extension sent lowercase.
        sha256 = override.sha256?.uppercased() ?? "NULL"
        
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
    /// Encode the event as eslogger does, plus Mac Monitor's own fields.
    ///
    /// eslogger writes either arm of the `file` union under `file`: the `es_file_t` as an object, or the path itself as
    /// a string (`null` when it's `NULL`). Which one is decided by the stored `file_type`, as eslogger decides it.
    /// Mac Monitor's own `file_path` spelling of the path arm is kept as an addition.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The encoder's error.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        //        try container.encode(id, forKey: .id)
        try container.encode(file_type, forKey: .file_type)
        try container.encode(file_type_string, forKey: .file_type_string)
        switch UInt32(truncatingIfNeeded: file_type) {
        case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH.rawValue:
            try container.encode(file_path, forKey: .file)
        case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE.rawValue:
            try container.encode(file, forKey: .file)
        default:
            /// eslogger can't encode another arm, so there's no value of its to match.
            try container.encodeIfPresent(file, forKey: .file)
        }
        try container.encodeIfPresent(file_path, forKey: .file_path)
        try container.encode(sha256, forKey: .sha256)
        try container.encode(signing_info, forKey: .signing_info)
    }
}
