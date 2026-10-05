//
//  FileDestination.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 5/7/25.
//

import Foundation


// Ensure File conforms to Codable and Equatable
public struct NewPath: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID()
    
    public var dir: File
    public var filename: String
    
    /// `mode_t`
    public var mode: Int?
    
    public init(from create: es_event_create_t) {
        self.dir = File(from: create.destination.new_path.dir.pointee)
        
        self.filename = create.destination.new_path.filename.string ?? ""
        
        self.mode = Int(create.destination.new_path.mode)
    }
    
    public init(from rename: es_event_rename_t) {
        self.dir = File(from: rename.destination.new_path.dir.pointee)
        
        self.filename = rename.destination.new_path.filename.string ?? ""
    }
    
    /// The new file's full path: ``dir`` and ``filename`` joined by one "/".
    public var fullPath: String {
        dir.path.hasSuffix("/") ? dir.path + filename : "\(dir.path)/\(filename)"
    }
}
