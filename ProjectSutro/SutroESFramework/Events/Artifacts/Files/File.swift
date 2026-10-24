//
//  File.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/16/25.
//

import Foundation


// Ensure File conforms to Codable and Equatable
public extension String {
    /// A path's last component, its file name: `macmonitor` for
    /// `/Applications/Mac Monitor.app/Contents/MacOS/macmonitor`. Read as a path, never through `URL(string:)`, which
    /// on macOS 13 has no URL for a path with a space, so the name was "".
    var lastPathComponent: String {
        (self as NSString).lastPathComponent
    }
}


public struct File: Identifiable, Codable, Equatable, Hashable {
    public var id = UUID.buffered()
    
    /// File system
    public var path: String
    public var path_truncated: Bool = false
    public var stat: Stat
    
    ///Mac Monitor Enrichment
    public var name: String {
        path.lastPathComponent
    }
    
    public init(from file: es_file_t) {
        self.path = file.path.string ?? ""
        self.path_truncated = file.path_truncated
        self.stat = Stat(from: file.stat)
    }
}
