//
//  File.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/16/25.
//

import Foundation


// Ensure File conforms to Codable and Equatable
public struct File: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID()
    
    /// File system
    public var path: String
    public var path_truncated: Bool = false
    public var stat: Stat
    
    ///Mac Monitor Enrichment
    public var name: String {
        (path as NSString).lastPathComponent
    }
    
    public init(from file: es_file_t) {
        self.path = String(cString: file.path.data)
        self.path_truncated = file.path_truncated
        self.stat = Stat(from: file.stat)
    }
}
