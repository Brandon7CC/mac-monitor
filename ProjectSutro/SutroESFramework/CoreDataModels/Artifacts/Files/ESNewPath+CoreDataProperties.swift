//
//  ESNewPath+CoreDataProperties.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 6/27/25.
//
//

public import Foundation
public import CoreData


extension ESNewPath {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESNewPath> {
        return NSFetchRequest<ESNewPath>(entityName: "ESNewPath")
    }

    @NSManaged public var id: UUID?
    @NSManaged public var filename: String?
    /// A create event's `mode_t`. A rename's new path has none (`nil`), and eslogger writes no `mode` for it.
    @NSManaged public var mode: NSNumber?
    @NSManaged public var dir: ESFile?

}

extension ESNewPath : Identifiable {

}
