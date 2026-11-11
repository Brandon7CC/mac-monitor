//
//  FileTypeReader.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - Reading a file's type
/// Reads the bytes a ``FileTypeClassifier`` needs from the file an event names, as a capture lane builds the event.
///
/// The Security Extension runs as root, so what it reads is held to the event's stat and process:
/// 1. Endpoint Security's stat decides first, with no I/O: only a regular file is read, one of 0 bytes is
///    ``FileType/empty``, and a dataless one (`SF_DATALESS`, a File Provider file not downloaded) isn't read.
/// 2. Nor is a file on a volume that isn't local (``LocalVolumes``).
/// 3. The path is opened with `O_NOFOLLOW_ANY` and `O_NONBLOCK`, and the open file's device and inode must be the
///    event's, else it's ``FileType/replaced``. So is a path with a symbolic link anywhere in it now: Endpoint
///    Security's paths have none, so one there means a folder above the file was swapped, maybe for a link to a
///    network volume the open would wait on. A path that's gone is looked up by the event's device and inode
///    (`fsgetpath`), and the file opened where it is now, held to the same checks: a writer that saves to a temporary
///    file renames it at once, often before the read, as zip(1) renames its `ziXXXXXX` to the archive's name.
/// 4. The open file must be one the event's process could read (``FileReader/canRead(_:of:)``).
/// 5. At most ``FileTypeClassifier/headerLength`` bytes are read from its start, plus a universal binary's slice's
///    header when it's past them, and a disk image's trailer when the start could be one's.
///
/// The read doesn't update access times or download dataless files (``ReadingThreadPolicy``). One gap is left: a
/// user who mounts a network volume on a folder of their own above the file, after the event, has the open walk
/// into it, as only a symbolic link is refused.
enum FileTypeReader {
    /// What a read gave, and whether the file read was the event's version of it.
    struct Reading: Equatable {
        /// The type, or `nil` when the file wasn't read.
        let type: FileType?
        /// Was the open file's size, modification time and change time the event's stat's? Only then is `type` the
        /// type of the version the event named, and one to remember.
        let isCurrent: Bool
    }

    /// The type of the file an event names.
    ///
    /// - Parameters:
    ///   - path: The file's path, as the event names it.
    ///   - info: The event's stat of the file.
    ///   - reader: Who the file is read for: the event's process's effective user and group.
    ///   - volumes: The capture lane's local volumes.
    /// - Returns: The type, ``FileType/empty`` or ``FileType/replaced``, or `nil` when it isn't read: not a regular
    ///   file, dataless, on a volume that isn't local, gone, or one `reader` couldn't read.
    static func fileType(at path: String, stat info: stat, for reader: FileReader,
                         volumes: LocalVolumes) -> FileType? {
        reading(at: path, stat: info, for: reader, volumes: volumes).type
    }

    /// The type of the file an event names, and whether it's the type of the event's version of the file.
    ///
    /// - Parameters:
    ///   - path: The file's path, as the event names it.
    ///   - info: The event's stat of the file.
    ///   - reader: Who the file is read for: the event's process's effective user and group.
    ///   - volumes: The capture lane's local volumes.
    /// - Returns: The reading: its type as ``fileType(at:stat:for:volumes:)`` gives it, current only when the file
    ///   was opened and still had the event's size, modification time and change time.
    static func reading(at path: String, stat info: stat, for reader: FileReader,
                        volumes: LocalVolumes) -> Reading {
        switch precheck(info) {
        case .read: break
        case .known(let type): return Reading(type: type, isCurrent: false)
        }
        guard volumes.isLocal(info.st_dev) else { return Reading(type: nil, isCurrent: false) }
        return ReadingThreadPolicy.whileReading { read(path, expecting: info, for: reader) }
    }

    /// What the event's stat decides before any I/O.
    enum Precheck: Equatable {
        /// Read the file.
        case read
        /// The answer, with no read: ``FileType/empty``, or `nil` for a file that isn't read.
        case known(FileType?)
    }

    /// What the event's stat says without reading: only a regular file that isn't dataless is read, and one of 0
    /// bytes is empty.
    ///
    /// - Parameter info: The event's stat of the file.
    /// - Returns: Whether to read it, or the answer.
    static func precheck(_ info: stat) -> Precheck {
        guard info.st_mode & S_IFMT == S_IFREG else { return .known(nil) }
        guard info.st_size > 0 else { return .known(.emptyFile) }
        return info.st_flags & UInt32(SF_DATALESS) == 0 ? .read : .known(nil)
    }

    /// Open the file, check it's still the event's and that the reader may read it, and sample it.
    ///
    /// - Parameters:
    ///   - path: The file's path.
    ///   - expected: The event's stat, whose device and inode the open file must have.
    ///   - reader: Who the file is read for.
    /// - Returns: The type, ``FileType/replaced``, or `nil` when it can't be opened or read, or `reader` couldn't,
    ///   and whether the open file had `expected`'s size, modification time and change time.
    private static func read(_ path: String, expecting expected: stat, for reader: FileReader) -> Reading {
        let descriptor = openForReading(path, expecting: expected)
        guard descriptor >= 0 else { return Reading(type: errno == ELOOP ? .replacedFile : nil, isCurrent: false) }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0 else { return Reading(type: nil, isCurrent: false) }
        guard info.st_dev == expected.st_dev, info.st_ino == expected.st_ino,
              info.st_mode & S_IFMT == S_IFREG else { return Reading(type: .replacedFile, isCurrent: false) }
        let isCurrent = isVersion(info, of: expected)
        guard reader.canRead(info, of: descriptor),
              let header = bytes(of: descriptor, count: FileTypeClassifier.headerLength, at: 0) else {
            return Reading(type: nil, isCurrent: isCurrent)
        }
        /// ``FileTypeClassifier/sliceOffsetToRead(header:preferring:)`` gives only offsets below `Int64.max`.
        let slice = FileTypeClassifier.sliceOffsetToRead(header: header).flatMap { offset in
            bytes(of: descriptor, count: MachOHeader.sliceHeaderLength, at: off_t(offset))
        }
        let type = FileTypeClassifier.classify(header: header, slice: slice)
        let length = FileTypeClassifier.trailerLength
        guard FileTypeClassifier.readsTrailer(for: type), info.st_size >= off_t(length) else {
            return Reading(type: type, isCurrent: isCurrent)
        }
        let trailer = bytes(of: descriptor, count: length, at: info.st_size - off_t(length))
        return Reading(type: FileTypeClassifier.classify(type, trailer: trailer), isCurrent: isCurrent)
    }

    /// Open a file for reading, without following a symbolic link anywhere on its path, or open it where it is now
    /// when its path is gone.
    ///
    /// - Parameters:
    ///   - path: The file's path, as the event names it.
    ///   - expected: The event's stat, whose device and inode find the file when `path` no longer exists.
    /// - Returns: The descriptor, or -1 with `errno` set by the last open tried.
    private static func openForReading(_ path: String, expecting expected: stat) -> Int32 {
        let flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW_ANY | O_CLOEXEC
        let descriptor = Darwin.open(path, flags)
        guard descriptor < 0, errno == ENOENT, let moved = currentPath(of: expected), moved != path else {
            return descriptor
        }
        return Darwin.open(moved, flags)
    }

    /// Where a file is now, by its device and inode: one system call, which fails for a file deleted since.
    ///
    /// - Parameter info: The event's stat of the file.
    /// - Returns: The file's path now, or `nil` when it has none.
    static func currentPath(of info: stat) -> String? {
        var volume = fsid_t(val: (info.st_dev, 0))
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fsgetpath(&buffer, buffer.count, &volume, info.st_ino) > 0 else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /// Is an open file the version of it an event's stat describes: the same size, modification time and change
    /// time? The change time can't be set from user space, so a file rewritten with its old modification time put
    /// back (`touch -r`) is still a new version.
    ///
    /// - Parameters:
    ///   - info: The open file's `fstat`.
    ///   - expected: The event's stat.
    /// - Returns: Whether the three match.
    static func isVersion(_ info: stat, of expected: stat) -> Bool {
        info.st_size == expected.st_size
            && info.st_mtimespec.tv_sec == expected.st_mtimespec.tv_sec
            && info.st_mtimespec.tv_nsec == expected.st_mtimespec.tv_nsec
            && info.st_ctimespec.tv_sec == expected.st_ctimespec.tv_sec
            && info.st_ctimespec.tv_nsec == expected.st_ctimespec.tv_nsec
    }

    /// Up to `count` bytes of an open file, with one `pread`.
    ///
    /// - Parameters:
    ///   - descriptor: The open file.
    ///   - count: How many bytes, at most.
    ///   - offset: Where they start.
    /// - Returns: The bytes read, fewer at the file's end, or `nil` when the read fails.
    private static func bytes(of descriptor: Int32, count: Int, at offset: off_t) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: count)
        let read = buffer.withUnsafeMutableBytes { pread(descriptor, $0.baseAddress, count, offset) }
        guard read >= 0 else { return nil }
        buffer.removeLast(count - read)
        return buffer
    }
}
