//
//  LaunchItemBundle+SigningGuard.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/5/26.
//

import Foundation


// MARK: - Before Security reads a bundle
extension LaunchItemBundle {
    /// The folders of a bundle, relative to it, whose files Security and CFBundle open by name to read its signature:
    /// the Info.plists, the executable (named by the Info.plist, or after the bundle), and the signature's files.
    static let signingFolders = ["", "Contents", "Contents/MacOS", "Contents/_CodeSignature", "_CodeSignature"]
    /// The Info.plists CFBundle reads whole, with no limit.
    static let infoPlistNames: Set<String> = ["Info.plist", "Info-macos.plist"]

    /// Can Security read a bundle's signature without waiting for good, or reading a file without bound?
    ///
    /// `SecStaticCodeCreateWithPath` opens the files it reads with a blocking `open(2)`, so a FIFO among them hangs it,
    /// and CFBundle reads an Info.plist whole. Which files it opens depends on the Info.plist: the executable is
    /// `CFBundleExecutable`, else `NSExecutable`, else the bundle's name without its extension, and a bundle without
    /// one has its signature in `_CodeSignature`. So every entry of the folders it opens files in by name
    /// (``signingFolders``) must be a regular file or a folder, and each Info.plist no longer than
    /// ``ProcessHelpers/fileContentsLimit``. Entries are only `stat`ed, never opened. A file swapped in after this
    /// check can still hang Security, which is why it reads off the capture lane (``StaticCodeSigning/read(path:)``).
    ///
    /// - Parameter path: The bundle directory.
    /// - Returns: `false` when a FIFO, device or socket (or a link to one) is where Security could open it, or an
    ///   Info.plist is too long.
    static func isSafeToReadSignature(at path: String) -> Bool {
        signingFolders.allSatisfy { folder in
            let folderPath = folder.isEmpty ? path : path.appendingPathComponent(folder)
            var info = stat()
            guard stat(folderPath, &info) == 0, info.st_mode & S_IFMT == S_IFDIR else { return true }
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: folderPath) else { return false }
            return names.allSatisfy { isSafeEntry(folderPath.appendingPathComponent($0)) }
        }
    }

    /// Is a folder's entry one Security can open and read safely? Only `stat(2)`, which never opens it.
    ///
    /// - Parameter path: The entry. A symbolic link is followed; a broken one is safe, as there's nothing to open.
    /// - Returns: `true` for a folder, a regular file (an Info.plist no longer than
    ///   ``ProcessHelpers/fileContentsLimit``), or nothing at all.
    private static func isSafeEntry(_ path: String) -> Bool {
        var info = stat()
        guard stat(path, &info) == 0 else { return true }
        switch info.st_mode & S_IFMT {
        case S_IFDIR:
            return true
        case S_IFREG:
            return !infoPlistNames.contains(path.lastPathComponent)
                || info.st_size <= off_t(ProcessHelpers.fileContentsLimit)
        default:
            return false
        }
    }

    /// Is a path a regular file, or nothing at all? Only `stat(2)`, which never opens it.
    ///
    /// - Parameter path: The path. A symbolic link is followed.
    /// - Returns: `false` for a directory, FIFO, device or socket.
    static func isRegularOrMissing(_ path: String) -> Bool {
        var info = stat()
        return stat(path, &info) != 0 || info.st_mode & S_IFMT == S_IFREG
    }
}
