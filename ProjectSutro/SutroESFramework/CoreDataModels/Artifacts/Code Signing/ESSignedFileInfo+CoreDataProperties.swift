//
//  ESSignedFileInfo+CoreDataProperties.swift
//  ProjectSutro
//
//  Created by Brandon Dalton on 8/18/25.
//
//

public import Foundation
public import CoreData


public typealias ESSignedFileInfoCoreDataPropertiesSet = NSSet

extension ESSignedFileInfo {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ESSignedFileInfo> {
        return NSFetchRequest<ESSignedFileInfo>(entityName: "ESSignedFileInfo")
    }

    @NSManaged public var id: UUID?
    @NSManaged public var cdhash: String
    @NSManaged public var signing_id: String?
    @NSManaged public var team_id: String?

}

extension ESSignedFileInfo : Identifiable {

}
