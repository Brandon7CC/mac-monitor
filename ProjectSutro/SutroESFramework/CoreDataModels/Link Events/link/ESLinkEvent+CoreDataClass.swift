//
//  ESLinkEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/1/23.
//
//

import Foundation
import CoreData

@objc(ESLinkEvent)
public class ESLinkEvent: NSManagedObject, Identifiable {
    @NSManaged public var source: ESFile
    @NSManaged public var target_dir: ESFile
    @NSManaged public var target_filename: String

    enum CodingKeys: CodingKey {
        case source
        case target_dir
        case target_filename
    }
    
    // MARK: - Custom Core Data initilizer for ESLinkEvent
    convenience init(from event: LinkEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        attach(ESFile.row(for: event.source, in: context), to: #keyPath(ESLinkEvent.source))
        attach(ESFile.row(for: event.target_dir, in: context), to: #keyPath(ESLinkEvent.target_dir))
        self.target_filename = event.target_filename
    }
}

// MARK: - Encodable conformance
extension ESLinkEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(source, forKey: .source)
        try container.encode(target_dir, forKey: .target_dir)
        try container.encode(target_filename, forKey: .target_filename)
    }
}
