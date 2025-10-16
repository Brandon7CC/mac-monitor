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
public class ESFileCreateEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id
        case destination_type
        case destination_type_string
        case destination
        case acl
        case is_quarantined
    }
    
    // MARK: - Custom Core Data initilizer for ESFileCreateEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let create: FileCreateEvent = message.event.create!
        let description = NSEntityDescription.entity(forEntityName: "ESFileCreateEvent", in: context)!
        self.init(entity: description, insertInto: context)
        
        self.destination_type = Int16(create.destination_type)
        self.destination_type_string = create.destination_type_string
        self.destination = ESFileDestination(from: create.destination, insertIntoManagedObjectContext: context)
        self.acl = create.acl
        self.is_quarantined = create.is_quarantined
    }
}

// MARK: - Encodable conformance
extension ESFileCreateEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(id, forKey: .id)
        
        try container.encode(destination_type, forKey: .destination_type)
        try container.encode(destination_type_string, forKey: .destination_type_string)
        try container.encode(destination, forKey: .destination)
        try container.encode(acl, forKey: .acl)
        try container.encode(is_quarantined, forKey: .is_quarantined)
    }
    
    public var targetPath: String {
        if let existingFile = destination.existing_file,
           let path = existingFile.path {
            return path
        } else if let newPath = destination.new_path {
            if let dir = newPath.dir?.path,
               let fileName = newPath.dir?.name {
                return "\(dir)/\(fileName)"
            }
        }
        
        return ""
    }
    
    public var fileName: String {
        return URL(string: targetPath)!.lastPathComponent
    }
}
