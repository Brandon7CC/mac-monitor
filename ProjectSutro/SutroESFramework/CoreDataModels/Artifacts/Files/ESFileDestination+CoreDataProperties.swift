//
//  ESFileDestination+CoreDataProperties.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/25.
//
//

public import Foundation
public import CoreData


extension ESFileDestination {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESFileDestination> {
        return NSFetchRequest<ESFileDestination>(entityName: "ESFileDestination")
    }

    @NSManaged public var id: UUID?
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

}

extension ESFileDestination : Identifiable {

}

