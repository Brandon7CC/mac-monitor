//
//  ProcessHelpers+ContainedFiles.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Reading files inside a directory
extension ProcessHelpers {
    /// The bytes of a regular file inside a directory, up to one more than ``fileContentsLimit``, read as
    /// ``openContainedRegularFile(_:in:)`` opens it.
    ///
    /// - Parameters:
    ///   - relativePath: The file's path inside the directory, such as `Contents/Info.plist`.
    ///   - directory: The directory.
    /// - Returns: The bytes, or `nil` if the file isn't one ``openContainedRegularFile(_:in:)`` opens, or can't be
    ///   read.
    static func readContainedRegularFile(_ relativePath: String, in directory: String) -> Data? {
        guard let file = openContainedRegularFile(relativePath, in: directory) else { return nil }
        return try? file.read(upToCount: fileContentsLimit + 1) ?? Data()
    }

    /// Open a regular file inside a directory for reading, without waiting, and only if it's really there.
    ///
    /// The Security Extension reads, as root, files a local user can name: a login item's Info.plist, an agent's
    /// plist. A symbolic link there, or a hard link to a file someone else owns, would have it read a file that user
    /// can't, such as another user's password hash, and hand its text to Mac Monitor. So each component below the
    /// directory is opened with `O_NOFOLLOW` (a symbolic link isn't followed: there's no file), and a file with more
    /// than one link is refused unless it's owned by its directory's owner. Every component is `stat`ed before it's
    /// opened, and opened with `O_NONBLOCK`, so a FIFO or device is never opened (``openRegularFile(at:)``).
    ///
    /// - Parameters:
    ///   - relativePath: The file's path inside the directory, such as `Contents/Info.plist`: no `.` or `..`.
    ///   - directory: The directory. A symbolic link to it, or above it, is followed.
    /// - Returns: The open file, closed when it's released, or `nil` if the path doesn't name a regular file there.
    static func openContainedRegularFile(_ relativePath: String, in directory: String) -> FileHandle? {
        let components = relativePath.split(separator: "/").map(String.init)
        guard let name = components.last, !components.contains(where: { $0 == "." || $0 == ".." }),
              var parent = openDirectory(directory, at: AT_FDCWD, following: true) else { return nil }
        defer { close(parent) }
        for component in components.dropLast() {
            guard let child = openDirectory(component, at: parent, following: false) else { return nil }
            close(parent)
            parent = child
        }
        var info = stat(), directoryInfo = stat()
        guard fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_mode & S_IFMT == S_IFREG else {
            return nil
        }
        let descriptor = openat(parent, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG, fstat(parent, &directoryInfo) == 0,
              info.st_nlink <= 1 || info.st_uid == directoryInfo.st_uid else { return nil }
        return file
    }

    /// Open a directory, only if it is one, without waiting.
    ///
    /// - Parameters:
    ///   - path: The directory's path, relative to `parent`, or absolute.
    ///   - parent: The directory `path` is relative to, or `AT_FDCWD`.
    ///   - following: Follow a symbolic link at `path` itself.
    /// - Returns: The descriptor, which the caller closes, or `nil` if `path` isn't a directory.
    private static func openDirectory(_ path: String, at parent: Int32, following: Bool) -> Int32? {
        var info = stat()
        guard fstatat(parent, path, &info, following ? 0 : AT_SYMLINK_NOFOLLOW) == 0,
              info.st_mode & S_IFMT == S_IFDIR else { return nil }
        let descriptor = openat(parent, path, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_CLOEXEC
                                | (following ? 0 : O_NOFOLLOW))
        return descriptor >= 0 ? descriptor : nil
    }
}
