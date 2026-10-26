//
//  ESFileCreateEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/22.
//
//

import Foundation
import CoreData

@objc(ESFileCreateEvent)
public class ESFileCreateEvent: NSManagedObject, Identifiable {
    @NSManaged public var acl: String?
    @NSManaged public var is_quarantined: Int16
    @NSManaged public var destination_type: Int16
    @NSManaged public var destination_type_string: String
    @NSManaged public var destination: ESFileDestination

    enum CodingKeys: CodingKey {
        case destination_type
        case destination_type_string
        case destination
        case acl
        case is_quarantined
    }
    
    // MARK: - Custom Core Data initilizer for ESFileCreateEvent
    convenience init(from event: FileCreateEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        self.destination_type = Int16(truncatingIfNeeded: event.destination_type)
        self.destination_type_string = event.destination_type_string
        self.destination = ESFileDestination(from: event.destination, insertIntoManagedObjectContext: context)
        self.acl = event.acl
        self.is_quarantined = event.is_quarantined
    }
}

// MARK: - Encodable conformance
extension ESFileCreateEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(destination_type, forKey: .destination_type)
        try container.encode(destination_type_string, forKey: .destination_type_string)
        try container.encode(destination, forKey: .destination)
        try container.encode(acl, forKey: .acl)
        try container.encode(is_quarantined, forKey: .is_quarantined)
    }
    
    /// The created file's path: the existing file's, or the new path's directory and file name joined.
    ///
    /// "" for a destination that can't be read.
    public var targetPath: String {
        if let existingFile = destination.existing_file,
           let path = existingFile.path {
            return path
        } else if let newPath = destination.new_path {
            if let dir = newPath.dir?.path,
               let fileName = newPath.filename {
                return "\(dir)/\(fileName)"
            }
        }
        
        return ""
    }
    
    /// The created file's name: the last component of ``targetPath``, or "" without one.
    ///
    /// Read as a path, not a URL: `URL(string:)` has no URL for "" and, on macOS 13, none for a path with a space.
    public var fileName: String {
        targetPath.lastPathComponent
    }
}
