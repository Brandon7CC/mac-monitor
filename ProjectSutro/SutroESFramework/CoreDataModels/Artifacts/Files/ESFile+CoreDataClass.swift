//
//  Executable+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/9/25.
//
//

import Foundation
import CoreData



@objc(ESFile)
public class ESFile: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, path, path_truncated, stat, name
    }
    
    // MARK: - Custom Core Data initilizer for File
    convenience init(
        from file: File,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        let description = NSEntityDescription.entity(forEntityName: "ESFile", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = file.id
        self.path = file.path
        self.name = file.name
        self.path_truncated = file.path_truncated
        self.stat = ESStat(
            from: file.stat,
            insertIntoManagedObjectContext: context
        )
    }
}

// MARK: - Encodable conformance
extension ESFile: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(id, forKey: .id)
        try container.encode(path, forKey: .path)
        try container.encode(name, forKey: .name)
        try container.encode(stat, forKey: .stat)
        try container.encode(path_truncated, forKey: .path_truncated)
    }
}
