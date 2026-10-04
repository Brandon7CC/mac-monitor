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
        if let mode = newPath.mode {
            self.mode = Int32(mode)
        }
    }
}

// MARK: - Encodable conformance and helper
extension ESNewPath: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        willAccessValue(forKey: "dir")
        defer { didAccessValue(forKey: "dir") }
        
        if let dirValue = primitiveValue(forKey: "dir"),
           let dirFile = dirValue as? ESFile,
           !dirFile.isFault {
            try container.encode(dirFile, forKey: .dir)
        }
        
        try container.encode(filename, forKey: .filename)
        try container.encodeIfPresent(mode, forKey: .mode)
    }
}
