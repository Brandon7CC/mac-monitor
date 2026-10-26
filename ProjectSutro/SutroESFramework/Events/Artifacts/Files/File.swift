//
//  File.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 3/16/25.
//

import Foundation


public extension String {
    /// A path's last component, its file name: `macmonitor` for
    /// `/Applications/Mac Monitor.app/Contents/MacOS/macmonitor`. Read as a path, never through `URL(string:)`, which
    /// on macOS 13 has no URL for a path with a space, so the name was "".
    var lastPathComponent: String {
        (self as NSString).lastPathComponent
    }

    /// A path less its last component, its folder: `/Applications/Mac Monitor.app/Contents/MacOS` for
    /// `/Applications/Mac Monitor.app/Contents/MacOS/macmonitor`. Read as a path, without a `URL` or the file system.
    var deletingLastPathComponent: String {
        (self as NSString).deletingLastPathComponent
    }

    /// A path with a component added, as written, without a `URL` or the file system.
    ///
    /// - Parameter component: The component, such as a file name or a relative path.
    /// - Returns: The path and the component joined by one "/".
    func appendingPathComponent(_ component: String) -> String {
        (self as NSString).appendingPathComponent(component)
    }
}


public struct File: Identifiable, Codable, Hashable {
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
