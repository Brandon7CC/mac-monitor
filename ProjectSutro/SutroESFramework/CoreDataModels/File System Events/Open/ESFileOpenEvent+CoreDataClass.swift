//
//  ESFileOpenEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/1/23.
//
//

import Foundation
import CoreData

@objc(ESFileOpenEvent)
public class ESFileOpenEvent: NSManagedObject {
    enum CodingKeys: CodingKey {
        case id, file, fflag
    }

    // MARK: - Custom Core Data initilizer for ESFileOpenEvent
    convenience init(from message: Message, insertIntoManagedObjectContext context: NSManagedObjectContext!) {
        let fileEvent: FileOpenEvent = message.event.open!
        let description = NSEntityDescription.entity(forEntityName: "ESFileOpenEvent", in: context)!
        self.init(entity: description, insertInto: context)
        self.id = fileEvent.id
        
        attach(ESFile.row(for: fileEvent.file, in: context), to: #keyPath(ESFileOpenEvent.file))
        self.fflag = fileEvent.fflag
    }
}

// MARK: - Encodable conformance
extension ESFileOpenEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(file, forKey: .file)
        try container.encode(fflag, forKey: .fflag)
    }
}
