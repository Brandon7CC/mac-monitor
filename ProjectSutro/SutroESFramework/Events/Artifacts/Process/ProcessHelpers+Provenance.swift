//
//  ProcessHelpers+Provenance.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Provenance
extension ProcessHelpers {
    /// The extended attribute a browser or other downloader records a file's origin in.
    static let whereFromsAttribute = "com.apple.metadata:kMDItemWhereFroms"
    /// The most bytes of ``whereFromsAttribute`` read: a larger one isn't a list of a few URLs.
    static let whereFromsLimit = 64 << 10

    /// Where a file was downloaded from: its `com.apple.metadata:kMDItemWhereFroms` attribute, a binary property list
    /// array that holds the download URL and then the page it was found on.
    ///
    /// - Parameter path: The file's or directory's path. A symbolic link is followed.
    /// - Returns: The array's strings, in order, or `nil` when the file has no such attribute, or it's larger than
    ///   ``whereFromsLimit`` or isn't an array.
    static func whereFroms(at path: String) -> [String]? {
        let size = getxattr(path, whereFromsAttribute, nil, 0, 0, 0)
        guard size > 0, size <= whereFromsLimit else { return nil }
        var data = Data(count: size)
        let read = data.withUnsafeMutableBytes { getxattr(path, whereFromsAttribute, $0.baseAddress, size, 0, 0) }
        guard read > 0,
              let list = try? PropertyListSerialization.propertyList(from: data.prefix(read), format: nil) as? [Any]
        else { return nil }
        return list.compactMap { $0 as? String }
    }

    /// When a file or directory was created: its `st_birthtimespec`.
    ///
    /// - Parameter path: The path. A symbolic link is followed.
    /// - Returns: The birth time, or `nil` if the path can't be `stat`ed.
    static func birthTime(at path: String) -> TimeSpec? {
        var info = stat()
        guard stat(path, &info) == 0 else { return nil }
        return TimeSpec(from: info.st_birthtimespec)
    }
}
