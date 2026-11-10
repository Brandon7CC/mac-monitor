//
//  ESFileRenameEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 2/17/23.
//
//

import Foundation
import CoreData
import OSLog

@objc(ESFileRenameEvent)
public class ESFileRenameEvent: NSManagedObject, Identifiable {
    @NSManaged public var source: ESFile
    @NSManaged public var destination_type: Int16
    @NSManaged public var destination_type_string: String
    @NSManaged public var destination: ESFileDestination
    
    /// @note Mac Monitor enrichment
    @NSManaged public var destination_path: String
    @NSManaged public var is_quarantined: Int16
    /// What the renamed file is by its content, read at capture (``FileRenameEvent/file_type``).
    @NSManaged public var file_type: String?
    /// A renamed Mach-O's `MH_*` file type (``FileRenameEvent/mach_o_type``).
    @NSManaged public var mach_o_type: String?

    enum CodingKeys: CodingKey {
        case source
        case destination_type, destination_type_string
        case destination, destination_path
        case is_quarantined
        case file_type, mach_o_type
    }
    
    // MARK: - Custom Core Data initilizer for ESFileRenameEvent
    convenience init(from event: FileRenameEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        attach(ESFile.row(for: event.source, in: context), to: #keyPath(ESFileRenameEvent.source))
        
        self.destination_type = Int16(truncatingIfNeeded: event.destination_type)
        self.destination_type_string = event.destination_type_string
        self.destination = ESFileDestination(from: event.destination, insertIntoManagedObjectContext: context)
        self.destination_path = event.destination_path
        
        self.is_quarantined = event.is_quarantined
        self.file_type = event.file_type
        self.mach_o_type = event.mach_o_type
    }
}

// MARK: - Encodable conformance
extension ESFileRenameEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(source, forKey: .source)
        try container.encode(destination_type, forKey: .destination_type)
        try container.encode(destination_type_string, forKey: .destination_type_string)
        try container.encode(destination, forKey: .destination)
        
        try container.encode(destination_path, forKey: .destination_path)
        try container.encode(is_quarantined, forKey: .is_quarantined)
        try container.encode(file_type, forKey: .file_type)
        try container.encode(mach_o_type, forKey: .mach_o_type)
    }
    
    public var destination_file_name: String {
        destination_path.lastPathComponent
    }
}
