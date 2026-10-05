//
//  ESNewPath+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/25.
//
//

import CoreData


@objc(ESNewPath)
public class ESNewPath: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case dir
        case filename
        case mode
    }
    
    // MARK: - Custom Core Data initilizer for ESNewPath
    convenience init(
        from newPath: NewPath,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        let description = NSEntityDescription.entity(forEntityName: "ESNewPath", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = newPath.id
        
        attach(ESFile.row(for: newPath.dir, in: context), to: #keyPath(ESNewPath.dir))
        self.filename = newPath.filename
        self.mode = newPath.mode.map { NSNumber(value: Int32(truncatingIfNeeded: $0)) }
    }
}

// MARK: - Encodable conformance and helper
extension ESNewPath: Encodable {
    /// Encode the new path with its directory, loading the directory if it isn't loaded yet.
    ///
    /// v2.0.0 through v2.1.0 wrote `dir` only when it was already loaded, which in an export it rarely was. `mode` is
    /// written only for a create event's new path: a rename's has none, and v2.0.0 through v2.1.0 wrote 0 for it.
    ///
    /// - Parameter encoder: The encoder.
    /// - Throws: The encoder's error.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(dir, forKey: .dir)
        try container.encode(filename, forKey: .filename)
        try container.encodeIfPresent(mode?.int32Value, forKey: .mode)
    }
}
