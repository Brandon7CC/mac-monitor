//
//  RootFileStore.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Root file store
/// One saved file in a directory only root can read or write (Security Extension context), such as the saved mute set
/// (``MuteStore``). It moves bytes. What they mean is up to the store built on it.
///
/// **Writes** go to a new `mkstemp` file in the same directory (0600), are flushed with `fsync`, then renamed over the
/// file, so a crash or power loss leaves the old file or the new one, never a mix.
///
/// **Reads** `lstat` first and open only a regular file owned by ``owner`` (never a link, FIFO or device), up to
/// ``Layout/maxBytes``. A file that can't be read can be moved aside (``moveAside()``).
///
/// **Trust:** the directory must be a real directory owned by ``owner`` that no one else can write. Otherwise the
/// store neither reads nor writes it.
public struct RootFileStore: Sendable {
    /// Where the Security Extension keeps its saved files: `/Library/Application Support` is `root:admin` 0755, so
    /// only root can create it. Created 0700 `root:wheel`.
    public static let systemDirectory = URL(fileURLWithPath:
        "/Library/Application Support/com.swiftlydetecting.agent.securityextension", isDirectory: true)

    /// What a store's file is called, how large it may be, and how messages name it.
    public struct Layout: Sendable, Equatable {
        /// The saved file, such as `mutes.json`.
        public let fileName: String
        /// Where a saved file that couldn't be read is kept, such as `mutes.unreadable.json`.
        public let unreadableFileName: String
        /// Temporary files being written start with this, such as `.mutes.`.
        public let temporaryPrefix: String
        /// The largest file read or written, in bytes.
        public let maxBytes: Int
        /// Names the file in messages, such as "saved mute set".
        public let noun: String

        /// - Parameters:
        ///   - fileName: The saved file.
        ///   - unreadableFileName: Where a saved file that couldn't be read is kept.
        ///   - temporaryPrefix: What temporary files being written start with.
        ///   - maxBytes: The largest file read or written.
        ///   - noun: Names the file in messages.
        public init(fileName: String, unreadableFileName: String, temporaryPrefix: String, maxBytes: Int,
                    noun: String) {
            self.fileName = fileName
            self.unreadableFileName = unreadableFileName
            self.temporaryPrefix = temporaryPrefix
            self.maxBytes = maxBytes
            self.noun = noun
        }
    }

    /// What ``read()`` found.
    public enum Read: Equatable {
        /// No directory, or no file.
        case missing
        /// The file can't be read, and why, as a sentence.
        case unreadable(String)
        /// The file is over ``Layout/maxBytes``, and how large it is.
        case tooLarge(bytes: Int)
        /// The file's bytes.
        case read(Data)
    }

    /// The directory holding the file.
    let directory: URL
    /// The directory's and file's owner: root, or the user running a test.
    let owner: uid_t
    /// The file's names and size cap.
    let layout: Layout

    /// - Parameters:
    ///   - directory: The directory holding the file.
    ///   - owner: Who must own the directory and file.
    ///   - layout: The file's names and size cap.
    public init(directory: URL = RootFileStore.systemDirectory, owner: uid_t = 0, layout: Layout) {
        self.directory = directory
        self.owner = owner
        self.layout = layout
    }

    /// The saved file.
    var fileURL: URL { directory.appendingPathComponent(layout.fileName) }

    /// Where an unreadable saved file is kept.
    var unreadableURL: URL { directory.appendingPathComponent(layout.unreadableFileName) }

    /// Read the file, after removing temporary files a crash left behind.
    ///
    /// - Returns: What was found.
    /// - Throws: ``RootFileStoreError/untrustedDirectory(_:)``, with nothing read.
    public func read() throws -> Read {
        guard try checkDirectory(creating: false) else { return .missing }
        removeLeftovers()
        return readFile()
    }

    /// Replace the file, atomically, creating the directory 0700 if it's missing.
    ///
    /// - Parameter data: The file's new bytes, at most ``Layout/maxBytes``.
    /// - Throws: ``RootFileStoreError``, with the old file left as it was and no temporary file left behind.
    public func write(_ data: Data) throws {
        _ = try checkDirectory(creating: true)
        guard data.count <= layout.maxBytes else {
            throw RootFileStoreError.writeFailed("The \(layout.noun) would be larger than \(maxSizeText).")
        }
        var template = Array(directory.appendingPathComponent(layout.temporaryPrefix + "XXXXXX").path.utf8CString)
        let descriptor = mkstemp(&template)
        guard descriptor >= 0 else { throw Self.failure("Couldn't create a file in \(directory.path)") }
        let temporary = template.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        var renamed = false
        defer { if !renamed { unlink(temporary) } }
        do {
            if let code = data.writeAll(to: descriptor) {
                throw Self.failure("Couldn't write the \(layout.noun)", code: code)
            }
            guard fchmod(descriptor, 0o600) == 0, fsync(descriptor) == 0 else {
                throw Self.failure("Couldn't flush the \(layout.noun) to disk")
            }
        } catch {
            close(descriptor)
            throw error
        }
        guard close(descriptor) == 0 else { throw Self.failure("Couldn't finish writing the \(layout.noun)") }
        guard rename(temporary, fileURL.path) == 0 else { throw Self.failure("Couldn't replace \(fileURL.path)") }
        renamed = true
    }

    /// Move an unreadable file aside, replacing an older one there.
    ///
    /// - Returns: Where it went, or `nil` if it couldn't be moved.
    public func moveAside() -> URL? {
        rename(fileURL.path, unreadableURL.path) == 0 ? unreadableURL : nil
    }

    /// Remove the file, such as a marker that's done its job.
    ///
    /// - Returns: `false` if it's there and couldn't be removed.
    @discardableResult
    public func remove() -> Bool {
        unlink(fileURL.path) == 0 || errno == ENOENT
    }

    /// ``Layout/maxBytes`` in words: "1 MiB", "64 KiB", or a count of bytes.
    var maxSizeText: String {
        let bytes = layout.maxBytes
        if bytes > 0, bytes % (1 << 20) == 0 { return "\(bytes >> 20) MiB" }
        if bytes > 0, bytes % (1 << 10) == 0 { return "\(bytes >> 10) KiB" }
        return "\(bytes) bytes"
    }
}


// MARK: - File system
extension RootFileStore {
    /// Check the directory is one only ``owner`` can write, creating it 0700 if asked.
    ///
    /// - Parameter creating: Create the directory if it's missing.
    /// - Returns: `false` if it's missing and wasn't to be created.
    /// - Throws: ``RootFileStoreError/untrustedDirectory(_:)``, or ``RootFileStoreError/writeFailed(_:)`` if it
    ///   can't be created.
    private func checkDirectory(creating: Bool) throws -> Bool {
        let path = directory.path
        var info = stat()
        if lstat(path, &info) != 0 {
            guard errno == ENOENT else { throw RootFileStoreError.untrustedDirectory("\(path) can't be examined.") }
            guard creating else { return false }
            guard mkdir(path, 0o700) == 0 || errno == EEXIST else { throw Self.failure("Couldn't create \(path)") }
            /// New directories take their parent's group (`admin`). 0700 makes it moot, but keep it `wheel`.
            if owner == 0 { chown(path, 0, 0) }
            guard lstat(path, &info) == 0 else { throw Self.failure("Couldn't examine \(path)") }
        }
        guard info.st_mode & S_IFMT == S_IFDIR else {
            throw RootFileStoreError.untrustedDirectory("\(path) isn't a directory.")
        }
        guard info.st_uid == owner else {
            throw RootFileStoreError.untrustedDirectory("\(path) isn't owned by \(ownerName).")
        }
        guard info.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
            throw RootFileStoreError.untrustedDirectory("Others can write to \(path).")
        }
        return true
    }

    /// Read the file without following a link or waiting on a FIFO: `lstat`, open only a regular file with
    /// `O_NOFOLLOW | O_NONBLOCK`, and check again with `fstat` in case it was replaced in between.
    ///
    /// - Returns: The bytes, up to one past ``Layout/maxBytes``, or why they can't be read.
    private func readFile() -> Read {
        let path = fileURL.path
        var info = stat()
        guard lstat(path, &info) == 0 else {
            return errno == ENOENT ? .missing : .unreadable("It can't be examined (\(errnoText())).")
        }
        let isOwnRegularFile: (stat) -> Bool = { $0.st_mode & S_IFMT == S_IFREG && $0.st_uid == owner }
        let notOwnRegularFile = Read.unreadable("It isn't a regular file owned by \(ownerName).")
        guard isOwnRegularFile(info) else { return notOwnRegularFile }
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { return .unreadable("It can't be opened (\(errnoText())).") }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        guard fstat(descriptor, &info) == 0, isOwnRegularFile(info) else { return notOwnRegularFile }
        guard info.st_size <= off_t(layout.maxBytes) else { return .tooLarge(bytes: Int(info.st_size)) }
        do {
            return .read(try file.read(upToCount: layout.maxBytes + 1) ?? Data())
        } catch {
            return .unreadable("It can't be read (\(error.localizedDescription)).")
        }
    }

    /// Names ``owner`` in messages.
    private var ownerName: String { owner == 0 ? "root" : "uid \(owner)" }

    /// Remove temporary files a crash left behind mid-write.
    private func removeLeftovers() {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        for name in names where name.hasPrefix(layout.temporaryPrefix) {
            unlink(directory.appendingPathComponent(name).path)
        }
    }

    /// A write failure, with why.
    ///
    /// - Parameters:
    ///   - what: What failed, as the start of a sentence.
    ///   - code: Why, as an `errno`: the current one unless given.
    /// - Returns: The error.
    private static func failure(_ what: String, code: Int32 = errno) -> RootFileStoreError {
        .writeFailed("\(what) (\(errnoText(code))).")
    }
}


// MARK: - Errors
/// Why a saved file can't be kept on disk.
public enum RootFileStoreError: Error, Equatable, CustomStringConvertible {
    /// The directory isn't one only its owner can write, so it's neither read nor written.
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
