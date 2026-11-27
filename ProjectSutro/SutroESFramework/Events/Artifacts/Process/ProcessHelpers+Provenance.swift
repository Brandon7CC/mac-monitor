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
        whereFroms { getxattr(path, whereFromsAttribute, $0, $1, 0, 0) }
    }

    /// Where an open file was downloaded from (``whereFroms(at:)``).
    ///
    /// - Parameter descriptor: The open file.
    /// - Returns: The array's strings, in order, or `nil` when it has none, or no such attribute.
    static func whereFroms(of descriptor: Int32) -> [String]? {
        whereFroms { fgetxattr(descriptor, whereFromsAttribute, $0, $1, 0, 0) }.flatMap { $0.isEmpty ? nil : $0 }
    }

    /// Where the program an exec runs was downloaded from: its executable's ``whereFroms(at:)``, else the bundle's it's
    /// the main executable of. An executable in one of the sealed system volume's folders wasn't downloaded, so it
    /// isn't read (``isInSystemFolder(_:)``).
    ///
    /// - Parameter executable: The exec's target executable.
    /// - Returns: The first strings found, or `nil` when neither has any.
    static func whereFroms(ofExecutable executable: File?) -> [String]? {
        guard let executable, !isInSystemFolder(executable.path) else { return nil }
        return whereFroms(at: executable.path).flatMap { $0.isEmpty ? nil : $0 }
            ?? bundleWhereFroms(ofExecutableAt: executable.path)
    }

    /// Where the bundle a program is the main executable of was downloaded from: an app's shell script, or its binary,
    /// has none of its own when the app came in an archive, but a downloaded `.app` folder does.
    ///
    /// - Parameter path: The program's path.
    /// - Returns: The bundle's ``whereFroms(at:)``, or `nil` when it isn't a bundle's main executable or the bundle has
    ///   none.
    static func bundleWhereFroms(ofExecutableAt path: String) -> [String]? {
        enclosingBundle(ofExecutableAt: path).flatMap { whereFroms(at: $0) }.flatMap { $0.isEmpty ? nil : $0 }
    }

    /// The sealed system volume's folders that programs run from.
    static let systemFolders = ["/System/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/"]

    /// Is a path in one of ``systemFolders``? The Data volume's own folders under `/System/Volumes/` aren't. The sealed
    /// system volume and the Data volume report the same `st_dev`, so it's told by the path. Only root writes the few
    /// folders in them that are firmlinks to the Data volume, such as `/System/Library/Caches`.
    ///
    /// - Parameter path: An executable's path.
    /// - Returns: Whether it's on the sealed system volume.
    static func isInSystemFolder(_ path: String) -> Bool {
        systemFolders.contains { path.hasPrefix($0) } && !path.hasPrefix("/System/Volumes/")
    }

    /// ``whereFromsAttribute`` read with `getxattr` or `fgetxattr`.
    ///
    /// - Parameter read: Reads the attribute into a buffer of a size, or with no buffer, returns its size.
    /// - Returns: The array's strings, in order, or `nil` when there's no such attribute, or it's larger than
    ///   ``whereFromsLimit`` or isn't an array.
    private static func whereFroms(reading read: (UnsafeMutableRawPointer?, Int) -> Int) -> [String]? {
        let size = read(nil, 0)
        guard size > 0, size <= whereFromsLimit else { return nil }
        var data = Data(count: size)
        let count = data.withUnsafeMutableBytes { read($0.baseAddress, size) }
        guard count > 0,
              let list = try? PropertyListSerialization.propertyList(from: data.prefix(count), format: nil) as? [Any]
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
