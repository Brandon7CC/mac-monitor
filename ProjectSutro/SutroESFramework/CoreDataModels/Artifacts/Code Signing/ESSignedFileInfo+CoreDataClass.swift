//
//  ESSignedFileInfo+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/18/25.
//
//

public import CoreData


@objc(ESSignedFileInfo)
public class ESSignedFileInfo: NSManagedObject, Identifiable {
    @NSManaged public var cdhash: String
    @NSManaged public var signing_id: String?
    @NSManaged public var team_id: String?

    enum CodingKeys: CodingKey {
        case cdhash
        case signing_id
        case team_id
    }
    
    // MARK: - Custom Core Data initilizer for ESSignedFileInfo
    convenience init(
        from singingInfo: SignedFileInfo,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        self.init(insertingInto: context)
        
        /// Uppercase like eslogger, also when an older Security Extension sent lowercase.
        cdhash = singingInfo.cdhash.uppercased()
        signing_id = singingInfo.signing_id
        team_id = singingInfo.team_id
    }
}

// MARK: - Encodable conformance and helper
extension ESSignedFileInfo: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(cdhash, forKey: .cdhash)
        try container.encode(signing_id, forKey: .signing_id)
        try container.encode(team_id, forKey: .team_id)
    }
}
