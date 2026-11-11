//
//  MuteStore.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Mute store
/// The saved mute set's file (Security Extension context): `mutes.json` in a directory only root can read or write,
/// kept by a ``RootFileStore``.
///
/// **Writes** go to a new `mkstemp` file in the same directory (0600), are flushed with `fsync`, then renamed over
/// `mutes.json`, so a crash or power loss leaves the old set or the new one, never a mix.
///
/// **Reads** `lstat` first and open only a regular file owned by the owner (never a link, FIFO or device), up to
/// ``MuteLimits/maxFileBytes``. A file that can't be read is moved aside to `mutes.unreadable.json`. A file from a
/// newer Mac Monitor is left untouched.
///
/// **Trust:** the directory must be a real directory owned by the owner that no one else can write. Otherwise the
/// store neither reads nor writes it.
public struct MuteStore: Sendable {
    /// Where the Security Extension keeps the saved set (``RootFileStore/systemDirectory``).
    public static let systemDirectory = RootFileStore.systemDirectory
    /// The saved set.
    static let fileName = "mutes.json"
    /// Where a saved set that couldn't be read is kept.
    static let unreadableFileName = "mutes.unreadable.json"
    /// Temporary files being written start with this.
    static let temporaryPrefix = ".mutes."
    /// The saved set's names and size cap.
    static let layout = RootFileStore.Layout(fileName: fileName, unreadableFileName: unreadableFileName,
                                             temporaryPrefix: temporaryPrefix, maxBytes: MuteLimits.maxFileBytes,
                                             noun: "saved mute set")
    
    /// The file.
    let file: RootFileStore
    
    /// - Parameters:
    ///   - directory: The directory holding the saved set.
    ///   - owner: Who must own the directory and file.
    public init(directory: URL = MuteStore.systemDirectory, owner: uid_t = 0) {
        file = RootFileStore(directory: directory, owner: owner, layout: Self.layout)
    }
    
    /// What ``load()`` found.
    public enum Loaded: Equatable {
        /// The saved set, what was left out of it (event names only a newer Mac Monitor knows), the default set
        /// revision it was last brought up to (`nil` for a set saved without one), and a newer one the user declined.
        case saved(MuteList, warnings: [String], defaultsRevision: Int? = nil, declinedRevision: Int? = nil)
        /// No saved set yet.
        case missing
        /// The file couldn't be read, and was moved to `kept` (if it could be).
        case unreadable(reason: String, kept: URL?)
        /// The file was written by a newer Mac Monitor, and is left untouched.
        case newer(version: Int)
    }
    
    /// The directory holding the saved set.
    var directory: URL { file.directory }
    
    /// The saved set's file.
    var fileURL: URL { file.fileURL }
    
    /// Where an unreadable saved set is kept.
    var unreadableURL: URL { file.unreadableURL }
    
    /// Read the saved set, after removing temporary files a crash left behind.
    ///
    /// - Returns: What was found.
    /// - Throws: ``MuteStoreError/untrustedDirectory(_:)``, with nothing read.
    public func load() throws -> Loaded {
        let data: Data
        switch try file.read() {
        case .missing:
            return .missing
        case .unreadable(let reason):
            return .unreadable(reason: reason, kept: file.moveAside())
        case .tooLarge(let bytes):
            return .unreadable(reason: "\(MuteFileError.tooLarge(bytes: bytes))", kept: file.moveAside())
        case .read(let bytes):
            data = bytes
        }
        do {
            let saved = try MuteFile.decode(data)
            let (list, warnings) = try saved.list(.saved)
            return .saved(list, warnings: warnings, defaultsRevision: saved.defaultsRevision,
                          declinedRevision: saved.declinedRevision)
        } catch MuteFileError.unsupportedVersion(let version) {
            return .newer(version: version)
        } catch {
            return .unreadable(reason: "\(error)", kept: file.moveAside())
        }
    }
    
    /// Replace the saved set, atomically.
    ///
    /// - Parameters:
    ///   - list: The set.
    ///   - defaultsRevision: The default set revision it's up to: the current one unless given.
    ///   - declinedRevision: A newer revision the user declined, if any.
    /// - Throws: ``MuteStoreError``, with the old file left as it was and no temporary file left behind.
    public func save(_ list: MuteList, defaultsRevision: Int = MuteSet.currentRevision,
                     declinedRevision: Int? = nil) throws {
        try file.write(MuteFile(list, defaultsRevision: defaultsRevision, declinedRevision: declinedRevision).encoded())
    }
}


// MARK: - Errors
/// Why the saved mute set can't be kept on disk (``RootFileStoreError``).
public typealias MuteStoreError = RootFileStoreError
