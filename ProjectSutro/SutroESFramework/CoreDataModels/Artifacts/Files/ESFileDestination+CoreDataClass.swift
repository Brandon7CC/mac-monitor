//
//  ESFileDestination+CoreDataClass.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/25.
//
//

public import CoreData


@objc(ESFileDestination)
public class ESFileDestination: NSManagedObject, Identifiable {
    @NSManaged public var existing_file: ESFile?

    /// The new path, read and written by key rather than through Core Data's generated accessor.
    ///
    /// Its selector, `new_path`, is in ARC's `new` family, so Swift takes the object the accessor returns as retained
    /// and releases it once more than Core Data retained it: the row was freed under the context, which crashed when
    /// the context was next reset.
    public var new_path: ESNewPath? {
        get { value(forKey: "new_path") as? ESNewPath }
        set { setValue(newValue, forKey: "new_path") }
    }

    enum CodingKeys: CodingKey {
        case existing_file
        case new_path
    }
    
    // MARK: - Custom Core Data initilizer for ESFileDestination
    convenience init(
        from destination: FileDestination,
        insertIntoManagedObjectContext context: NSManagedObjectContext!
    ) {
        self.init(insertingInto: context)
        
        switch destination {
        case .existing_file(let existingFile):
            attach(ESFile.row(for: existingFile, in: context), to: #keyPath(ESFileDestination.existing_file))
        case .new_path(let newPath):
            self.new_path = ESNewPath(from: newPath, insertIntoManagedObjectContext: context)
        case .unknown:
            /// Neither: the destination encodes as `{}`.
            break
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
