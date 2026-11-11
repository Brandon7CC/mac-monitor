//
//  ESFileCloseEvent+CoreDataClass.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 4/2/23.
//
//

import Foundation
import CoreData

@objc(ESFileCloseEvent)
public class ESFileCloseEvent: NSManagedObject, Identifiable {
    @NSManaged public var target: ESFile
    @NSManaged public var modified: Bool
    
    // message >= 6
    @NSManaged public var was_mapped_writable: Bool
    /// What a modified file's first bytes are, read at capture: a type identifier, `empty`, `dyld_shared_cache` or
    /// `replaced`. `nil` for an unmodified close, when the file wasn't read, or when the record had none.
    @NSManaged public var file_type: String?
    /// The `MH_*` file type of a modified Mach-O, read at capture. `nil` for any other file, or as ``file_type`` is.
    @NSManaged public var mach_o_type: String?

    enum CodingKeys: CodingKey {
        case target
        case modified
        case was_mapped_writable
        case file_type
        case mach_o_type
    }
    
    // MARK: - Custom Core Data initilizer for ESFileCloseEvent
    convenience init(from event: FileCloseEvent, message: Message, in context: NSManagedObjectContext!) {
        self.init(insertingInto: context)
        
        attach(ESFile.row(for: event.target, in: context), to: #keyPath(ESFileCloseEvent.target))
        self.modified = event.modified
        self.was_mapped_writable = event.was_mapped_writable ?? false
        self.file_type = event.file_type
        self.mach_o_type = event.mach_o_type
    }
}

// MARK: - Encodable conformance
extension ESFileCloseEvent: Encodable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(target, forKey: .target)
        try container.encode(modified, forKey: .modified)
        try container
            .encodeIfPresent(was_mapped_writable, forKey: .was_mapped_writable)
        /// Always both keys: `null` for an unmodified close, when the file wasn't read, and in a record from eslogger
        /// or Mac Monitor before 3.1.0, as opening a trace never reads the file.
        try container.encode(file_type, forKey: .file_type)
        try container.encode(mach_o_type, forKey: .mach_o_type)
    }
}
