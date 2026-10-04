//
//  ESFileDestination+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/25.
//
//

public import CoreData


@objc(ESFileDestination)
public class ESFileDestination: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case existing_file
        case new_path
    }
    
    // MARK: - Custom Core Data initilizer for ESFileDestination
    convenience init(
        from destination: FileDestination,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        let description = NSEntityDescription.entity(forEntityName: "ESFileDestination", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = UUID()
        
        switch destination {
        case .existing_file(let existingFile):
            attach(ESFile.row(for: existingFile, in: context), to: #keyPath(ESFileDestination.existing_file))
        case .new_path(let newPath):
            self.new_path = ESNewPath(from: newPath, insertIntoManagedObjectContext: context)
        }
    }
}

// MARK: - Encodable conformance
extension ESFileDestination: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        if let existingFile = self.value(forKey: "existing_file") as? ESFile {
            try container.encode(existingFile, forKey: .existing_file)
        }
        
        if let newPath = self.value(forKey: "new_path") as? ESNewPath {
            try container.encode(newPath, forKey: .new_path)
        }
    }
}
