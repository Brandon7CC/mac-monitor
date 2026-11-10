//
//  FileIdentity.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Which file a path names
/// Which file a path must still name when it's read: the device, inode, and size ES reported for it.
///
/// A script can replace itself between its exec and Mac Monitor's read, so the text read would be a decoy's. Opened,
/// a file is only read when it's still the one ES saw.
struct FileIdentity: Hashable {
    /// The device the file is on (`st_dev`).
    let device: Int64
    /// The file's inode (`st_ino`).
    let inode: Int64
    /// The file's size in bytes (`st_size`).
    let size: Int64

    /// The identity ES reported.
    ///
    /// - Parameter info: The file's `stat`, as an event carries it.
    init(_ info: Stat) {
        (device, inode, size) = (info.st_dev, info.st_ino, info.st_size)
    }

    /// The identity of a file as it is now.
    ///
    /// - Parameter info: The file's `stat`, such as an open file's `fstat`.
    init(_ info: stat) {
        (device, inode, size) = (Int64(info.st_dev), Int64(bitPattern: info.st_ino), Int64(info.st_size))
    }

    /// Is a file this one?
    ///
    /// - Parameter info: The file's `stat`.
    /// - Returns: Whether its device, inode, and size all match.
    func matches(_ info: stat) -> Bool {
        FileIdentity(info) == self
    }
}
