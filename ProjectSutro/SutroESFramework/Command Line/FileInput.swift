//
//  FileInput.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - File input
/// Reads a file `macmonitor` imports, as the user running it: `mute import` and `indicators import`. The Security
/// Extension never opens a caller's path, so this is the only read.
public enum FileInput {
    /// Read a regular file, never a device or a pipe that could hang, or standard input for `-`, at most one byte
    /// past `limit`, so a larger one is reported as too large without reading it all.
    ///
    /// - Parameters:
    ///   - path: The path, or `-`.
    ///   - limit: The most bytes the import takes.
    /// - Returns: The bytes: more than `limit` only when the file is too large.
    /// - Throws: A `POSIXError`, or `CocoaError(.fileReadUnsupportedScheme)` for something that isn't a regular file.
    public static func read(_ path: String, upTo limit: Int) throws -> Data {
        guard path != "-" else {
            return try FileHandle.standardInput.read(upToCount: limit + 1) ?? Data()
        }
        let descriptor = open(path, O_RDONLY | O_NONBLOCK)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_mode & S_IFMT == S_IFREG else {
            throw CocoaError(.fileReadUnsupportedScheme)
        }
        return try file.read(upToCount: limit + 1) ?? Data()
    }
}
