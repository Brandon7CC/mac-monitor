//
//  FileTypeMemory.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/6/26.
//

import Foundation


// MARK: - File type memory
/// The file types a capture lane has read, for the mmaps that map the same files again and again: every process maps
/// the same libraries and frameworks.
///
/// A mapped file's type is remembered by its device, inode, size, modification time and change time, all from the
/// event's stat, and by the mapping process's user and group: an mmap of a file seen before reads nothing, no system
/// call. A file changed since has a new change time, which user space can't set, so it's read again even when its
/// modification time was put back. Only a type read from the event's version of the file is remembered: never a file
/// that wasn't read, nor one that changed between the event and the read. Keyed by the reader too, a hit gives the
/// answer a miss would: a file refused to one user (``FileReader/canRead(_:of:)``) is never given them from another's
/// mmap. On an M5 (`FileTypePerformanceTests`, built with -O), a hit took 0.037 µs (`enrich.file_type.hit`), and a
/// miss on a copy of `/bin/ls` 13.2 µs for root (`enrich.file_type.miss.root`) and 34.5 µs for a user, whose search
/// of each folder above the file is checked (`enrich.file_type.miss`).
///
/// A close isn't looked up: a modified close's file has just changed. What it reads is remembered apart, for a rename
/// of the file it closed: a file written under one name and renamed into place, as a safe save writes and as a
/// payload is staged, is named by its close's read, with no system call. The rename's stat of the file it moves is the
/// version its close read, so a rename of anything else, or of a file changed since, misses and is read where it now
/// is.
///
/// Bounded like ``ProcessPathMemory``: two generations of up to `capacity` files each. When the newer one fills up
/// the older one is dropped, and a file found in the older one moves to the newer one, so the libraries mapped most
/// stay. Closes keep ``closeCapacity`` each, since a rename follows its close at once, and never push a mapped
/// library out.
///
/// Not thread-safe: each capture lane keeps its own, used under its gate.
final class FileTypeMemory {
    /// The files a capture lane's memory holds per generation.
    static let laneCapacity = 4_096
    /// The closed files it holds per generation, for the renames that follow them.
    static let closeCapacity = 256

    /// A file's version, from the event's stat, and who it was read for.
    private struct Key: Hashable {
        let device: Int32
        let inode: UInt64
        let size: Int64
        let modified: Int
        let modifiedNanoseconds: Int
        let changed: Int
        let changedNanoseconds: Int
        let reader: FileReader

        /// - Parameters:
        ///   - info: The event's stat of the file.
        ///   - reader: Who the file is read for.
        init(_ info: stat, for reader: FileReader) {
            (device, inode, size, self.reader) = (info.st_dev, info.st_ino, info.st_size, reader)
            (modified, modifiedNanoseconds) = (info.st_mtimespec.tv_sec, info.st_mtimespec.tv_nsec)
            (changed, changedNanoseconds) = (info.st_ctimespec.tv_sec, info.st_ctimespec.tv_nsec)
        }
    }

    /// Two generations of file types, the newer of which a hit in the older moves to.
    private struct Generations {
        /// The newer and the older generation.
        var recent: [Key: FileType] = [:], older: [Key: FileType] = [:]
        /// The files each generation holds.
        let capacity: Int

        /// - Parameter key: A file's version.
        /// - Returns: Its type, if either generation has it.
        mutating func find(_ key: Key) -> FileType? {
            if let type = recent[key] { return type }
            guard let type = older.removeValue(forKey: key) else { return nil }
            store(type, for: key)
            return type
        }

        /// Keep a type the newer generation doesn't have, starting a new generation when it's full.
        ///
        /// - Parameters:
        ///   - type: The type.
        ///   - key: The file's version.
        mutating func store(_ type: FileType, for key: Key) {
            if recent.count >= capacity {
                older = recent
                recent = [:]
            }
            recent[key] = type
        }

        /// How many files the two generations hold.
        var count: Int { recent.count + older.count }
    }

    /// The mapped files' types, and the closed files'.
    private var mapped: Generations, closed: Generations
    /// The lane's local volumes.
    let volumes: LocalVolumes

    /// - Parameters:
    ///   - capacity: The mapped files each generation holds.
    ///   - closeCapacity: The closed files each generation holds.
    ///   - volumes: The lane's local volumes.
    init(capacity: Int = laneCapacity, closeCapacity: Int = closeCapacity, volumes: LocalVolumes = LocalVolumes()) {
        (mapped, closed) = (Generations(capacity: capacity), Generations(capacity: closeCapacity))
        self.volumes = volumes
    }

    /// The type of a file an mmap maps: remembered, or else read and remembered.
    ///
    /// - Parameters:
    ///   - path: The file's path.
    ///   - info: The event's stat of the file.
    ///   - reader: Who the file is read for: the mapping process's effective user and group.
    /// - Returns: The type, or `nil` when it isn't read (``FileTypeReader/fileType(at:stat:for:volumes:)``).
    func mappedFileType(at path: String, stat info: stat, for reader: FileReader) -> FileType? {
        if case .known(let type) = FileTypeReader.precheck(info) { return type }
        let key = Key(info, for: reader)
        if let type = mapped.find(key) { return type }
        let reading = FileTypeReader.reading(at: path, stat: info, for: reader, volumes: volumes)
        if let type = reading.type, reading.isCurrent, type != .replacedFile { mapped.store(type, for: key) }
        return reading.type
    }

    /// The type of a file a modified close closed, read now: the file has just changed. A type read from the event's
    /// version of the file is remembered for a rename of it.
    ///
    /// - Parameters:
    ///   - path: The file's path.
    ///   - info: The event's stat of the file.
    ///   - reader: Who the file is read for: the closing process's effective user and group.
    /// - Returns: The type, or `nil` when it isn't read (``FileTypeReader/fileType(at:stat:for:volumes:)``).
    func closedFileType(at path: String, stat info: stat, for reader: FileReader) -> FileType? {
        let reading = FileTypeReader.reading(at: path, stat: info, for: reader, volumes: volumes)
        if let type = reading.type, reading.isCurrent, type != .replacedFile {
            closed.store(type, for: Key(info, for: reader))
        }
        return reading.type
    }

    /// The type of a file a rename moved: its close's, when that close read the version the rename moved, or a
    /// mapping's, or else read where the file now is. The read isn't remembered: a rename changes the file's change
    /// time, so the file read is never the event's version.
    ///
    /// - Parameters:
    ///   - path: Where the file is now: the rename's destination.
    ///   - info: The event's stat of the file it moved, from before the rename.
    ///   - reader: Who the file is read for: the renaming process's effective user and group.
    /// - Returns: The type, or `nil` when it isn't read (``FileTypeReader/fileType(at:stat:for:volumes:)``).
    func renamedFileType(at path: String, stat info: stat, for reader: FileReader) -> FileType? {
        if case .known(let type) = FileTypeReader.precheck(info) { return type }
        let key = Key(info, for: reader)
        if let type = closed.find(key) ?? mapped.find(key) { return type }
        return FileTypeReader.fileType(at: path, stat: info, for: reader, volumes: volumes)
    }

    /// How many mapped files the two generations hold.
    var count: Int { mapped.count }

    /// How many closed files the two generations hold.
    var closedCount: Int { closed.count }
}
