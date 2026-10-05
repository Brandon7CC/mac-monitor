//
//  MuteStore.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Mute store
/// The saved mute set's file (Security Extension context): `mutes.json` in a directory only root can read or write.
///
/// **Writes** go to a new `mkstemp` file in the same directory (0600), are flushed with `fsync`, then renamed over
/// `mutes.json`, so a crash or power loss leaves the old set or the new one, never a mix.
///
/// **Reads** `lstat` first and open only a regular file owned by ``owner`` (never a link, FIFO or device), up to
/// ``MuteLimits/maxFileBytes``. A file that can't be read is moved aside to `mutes.unreadable.json`. A file from a
/// newer Mac Monitor is left untouched.
///
/// **Trust:** the directory must be a real directory owned by ``owner`` that no one else can write. Otherwise the
/// store neither reads nor writes it.
public struct MuteStore: Sendable {
    /// Where the Security Extension keeps the saved set: `/Library/Application Support` is `root:admin` 0755, so
    /// only root can create it. Created 0700 `root:wheel`.
    public static let systemDirectory = URL(fileURLWithPath:
        "/Library/Application Support/com.swiftlydetecting.agent.securityextension", isDirectory: true)
    /// The saved set.
    static let fileName = "mutes.json"
    /// Where a saved set that couldn't be read is kept.
    static let unreadableFileName = "mutes.unreadable.json"
    /// Temporary files being written start with this.
    static let temporaryPrefix = ".mutes."
    
    /// The directory holding the saved set.
    let directory: URL
    /// The directory's and file's owner: root, or the user running a test.
    let owner: uid_t
    
    /// - Parameters:
    ///   - directory: The directory holding the saved set.
    ///   - owner: Who must own the directory and file.
    public init(directory: URL = MuteStore.systemDirectory, owner: uid_t = 0) {
        self.directory = directory
        self.owner = owner
    }
    
    /// What ``load()`` found.
    public enum Loaded: Equatable {
        /// The saved set, and what was left out of it (event names only a newer Mac Monitor knows).
        case saved(MuteList, warnings: [String])
        /// No saved set yet.
        case missing
        /// The file couldn't be read, and was moved to `kept` (if it could be).
        case unreadable(reason: String, kept: URL?)
        /// The file was written by a newer Mac Monitor, and is left untouched.
        case newer(version: Int)
    }
    
    /// The saved set's file.
    var fileURL: URL { directory.appendingPathComponent(Self.fileName) }
    
    /// Where an unreadable saved set is kept.
    var unreadableURL: URL { directory.appendingPathComponent(Self.unreadableFileName) }
    
    /// Read the saved set, after removing temporary files a crash left behind.
    ///
    /// - Returns: What was found.
    /// - Throws: ``MuteStoreError/untrustedDirectory(_:)``, with nothing read.
    public func load() throws -> Loaded {
        guard try checkDirectory(creating: false) else { return .missing }
        removeLeftovers()
        let data: Data
        switch readFile() {
        case .missing:
            return .missing
        case .unreadable(let reason):
            return .unreadable(reason: reason, kept: moveAside())
        case .read(let bytes):
            data = bytes
        }
        do {
            let (list, warnings) = try MuteFile.decode(data).list(.saved)
            return .saved(list, warnings: warnings)
        } catch MuteFileError.unsupportedVersion(let version) {
            return .newer(version: version)
        } catch {
            return .unreadable(reason: "\(error)", kept: moveAside())
        }
    }
    
    /// Replace the saved set, atomically.
    ///
    /// - Parameter list: The set.
    /// - Throws: ``MuteStoreError``, with the old file left as it was and no temporary file left behind.
    public func save(_ list: MuteList) throws {
        _ = try checkDirectory(creating: true)
        let data = MuteFile(list).encoded()
        guard data.count <= MuteLimits.maxFileBytes else {
            throw MuteStoreError.writeFailed("The saved mute set would be larger than 1 MiB.")
        }
        var template = Array(directory.appendingPathComponent(Self.temporaryPrefix + "XXXXXX").path.utf8CString)
        let descriptor = mkstemp(&template)
        guard descriptor >= 0 else { throw Self.failure("Couldn't create a file in \(directory.path)") }
        let temporary = template.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        var renamed = false
        defer { if !renamed { unlink(temporary) } }
        do {
            if let code = data.writeAll(to: descriptor) {
                throw Self.failure("Couldn't write the saved mute set", code: code)
            }
            guard fchmod(descriptor, 0o600) == 0, fsync(descriptor) == 0 else {
                throw Self.failure("Couldn't flush the saved mute set to disk")
            }
        } catch {
            close(descriptor)
            throw error
        }
        guard close(descriptor) == 0 else { throw Self.failure("Couldn't finish writing the saved mute set") }
        guard rename(temporary, fileURL.path) == 0 else { throw Self.failure("Couldn't replace \(fileURL.path)") }
        renamed = true
    }
}


// MARK: - File system
extension MuteStore {
    /// What reading the file gave.
    private enum Read {
        case missing
        case unreadable(String)
        case read(Data)
    }
    
    /// Check the directory is one only ``owner`` can write, creating it 0700 if asked.
    ///
    /// - Parameter creating: Create the directory if it's missing.
    /// - Returns: `false` if it's missing and wasn't to be created.
    /// - Throws: ``MuteStoreError/untrustedDirectory(_:)``, or ``MuteStoreError/writeFailed(_:)`` if it can't be
    ///   created.
    private func checkDirectory(creating: Bool) throws -> Bool {
        let path = directory.path
        var info = stat()
        if lstat(path, &info) != 0 {
            guard errno == ENOENT else { throw MuteStoreError.untrustedDirectory("\(path) can't be examined.") }
            guard creating else { return false }
            guard mkdir(path, 0o700) == 0 || errno == EEXIST else { throw Self.failure("Couldn't create \(path)") }
            /// New directories take their parent's group (`admin`); 0700 makes it moot, but keep it `wheel`.
            if owner == 0 { chown(path, 0, 0) }
            guard lstat(path, &info) == 0 else { throw Self.failure("Couldn't examine \(path)") }
        }
        guard info.st_mode & S_IFMT == S_IFDIR else {
            throw MuteStoreError.untrustedDirectory("\(path) isn't a directory.")
        }
        guard info.st_uid == owner else {
            throw MuteStoreError.untrustedDirectory("\(path) isn't owned by \(ownerName).")
        }
        guard info.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
            throw MuteStoreError.untrustedDirectory("Others can write to \(path).")
        }
        return true
    }
    
    /// Read the file without following a link or waiting on a FIFO: `lstat`, open only a regular file with
    /// `O_NOFOLLOW | O_NONBLOCK`, and check again with `fstat` in case it was replaced in between.
    ///
    /// - Returns: The bytes, up to one past ``MuteLimits/maxFileBytes``, or why they can't be read.
    private func readFile() -> Read {
        let path = fileURL.path
        var info = stat()
        guard lstat(path, &info) == 0 else {
            return errno == ENOENT ? .missing : .unreadable("It can't be examined (\(Self.errorText())).")
        }
        let isOwnRegularFile: (stat) -> Bool = { $0.st_mode & S_IFMT == S_IFREG && $0.st_uid == owner }
        let notOwnRegularFile = Read.unreadable("It isn't a regular file owned by \(ownerName).")
        guard isOwnRegularFile(info) else { return notOwnRegularFile }
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return .unreadable("It can't be opened (\(Self.errorText())).") }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        guard fstat(descriptor, &info) == 0, isOwnRegularFile(info) else { return notOwnRegularFile }
        guard info.st_size <= off_t(MuteLimits.maxFileBytes) else {
            return .unreadable("\(MuteFileError.tooLarge(bytes: Int(info.st_size)))")
        }
        do {
            return .read(try file.read(upToCount: MuteLimits.maxFileBytes + 1) ?? Data())
        } catch {
            return .unreadable("It can't be read (\(error.localizedDescription)).")
        }
    }
    
    /// Names ``owner`` in messages.
    private var ownerName: String { owner == 0 ? "root" : "uid \(owner)" }
    
    /// Move an unreadable file aside, replacing an older one there.
    ///
    /// - Returns: Where it went, or `nil` if it couldn't be moved.
    private func moveAside() -> URL? {
        rename(fileURL.path, unreadableURL.path) == 0 ? unreadableURL : nil
    }
    
    /// Remove temporary files a crash left behind mid-write.
    private func removeLeftovers() {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        for name in names where name.hasPrefix(Self.temporaryPrefix) {
            unlink(directory.appendingPathComponent(name).path)
        }
    }
    
    /// A write failure, with why.
    ///
    /// - Parameters:
    ///   - what: What failed, as the start of a sentence.
    ///   - code: Why, as an `errno`: the current one unless given.
    /// - Returns: The error.
    private static func failure(_ what: String, code: Int32 = errno) -> MuteStoreError {
        .writeFailed("\(what) (\(errorText(code))).")
    }
    
    /// An `errno` in words.
    ///
    /// - Parameter code: The `errno`: the current one unless given.
    /// - Returns: `strerror(code)`.
    private static func errorText(_ code: Int32 = errno) -> String {
        String(cString: strerror(code))
    }
}


// MARK: - Errors
/// Why the saved mute set can't be kept on disk.
public enum MuteStoreError: Error, Equatable, CustomStringConvertible {
    /// The directory isn't one only root can write, so it's neither read nor written.
    case untrustedDirectory(String)
    /// The file couldn't be written. The old one is left as it was.
    case writeFailed(String)
    
    /// The problem, as a sentence.
    public var description: String {
        switch self {
        case .untrustedDirectory(let reason), .writeFailed(let reason): return reason
        }
    }
}
