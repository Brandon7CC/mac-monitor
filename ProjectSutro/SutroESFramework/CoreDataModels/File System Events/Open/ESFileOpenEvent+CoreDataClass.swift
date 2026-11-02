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
public class ESFileOpenEvent: NSManagedObject, Identifiable {
    @NSManaged public var file: ESFile
    @NSManaged public var fflag: Int32

    enum CodingKeys: CodingKey {
        case file, fflag
    }

    // MARK: - Custom Core Data initilizer for ESFileOpenEvent
    convenience init(from event: FileOpenEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        attach(ESFile.row(for: event.file, in: context), to: #keyPath(ESFileOpenEvent.file))
        self.fflag = event.fflag
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
