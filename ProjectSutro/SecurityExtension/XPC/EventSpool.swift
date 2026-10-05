//
//  EventSpool.swift
//  SecurityExtension
//
//  Created by Brandon Dalton on 10/1/26.
//

import Foundation
import SutroESFramework


// MARK: - Event spool
/// A first-in, first-out queue of serialized events backed by files (Security Extension context).
///
/// `SensorService` doesn't drop events when Mac Monitor falls behind. It keeps a bounded number in memory and spills the
/// rest here, similar to how Process Monitor backs its event log with a file. Events are read back in the order they were
/// written.
///
/// **Bounds:** this is a root process writing to the system's Data volume, so a Mac Monitor that stays connected but stops
/// replying (paused in a debugger, `SIGSTOP`ped) must not fill the disk. The spool refuses events once it holds
/// ``maxSize`` bytes, or once the volume's free space drops below ``minFreeSpace`` (checked as each segment starts).
///
/// **Segments:** the spool is a chain of files of about ``segmentSize`` bytes. Writes go to the newest segment and a new
/// one starts once it's full. Reads come from the oldest, which is deleted as soon as it's been read. So during a long
/// overload disk use tracks the unsent backlog (plus at most one already-read segment, the one still being written), not
/// everything that has passed through the spool.
///
/// Records are a little-endian `UInt32` length followed by that many bytes of JSON, and never span segments. Files live
/// in a root-only (`0700`) directory and are created `0600`. Every remaining segment is deleted when the spool is
/// released.
///
/// Not thread-safe: Mac Monitor's ``EventBatcher`` only touches it on its queue.
final class EventSpool: EventBacklog {
    /// Where spool files live. Anything left here by a crashed extension is removed by ``removeLeftovers()``.
    static let directory: URL = FileManager.default.temporaryDirectory
        .appendingPathComponent("com.swiftlydetecting.agent.securityextension.spool", isDirectory: true)

    /// Start a new segment once the current one reaches this size.
    static let segmentSize: UInt64 = 64 * 1024 * 1024

    /// The most unread bytes the spool holds (about 800,000 events) before refusing new events.
    static let maxSize: UInt64 = 4 * 1024 * 1024 * 1024

    /// The free space left on the volume for everything else. No new segment starts below this.
    static let minFreeSpace: Int64 = 5 * 1024 * 1024 * 1024

    /// Segment files, oldest first. The last one is being written; the first one is being read.
    private var segments: [URL] = []
    private var writer: FileHandle
    private var writerOffset: UInt64 = 0
    private var reader: FileHandle

    /// The number of events written but not yet read.
    private(set) var count: Int = 0

    /// The bytes of records written but not yet read.
    private(set) var size: UInt64 = 0

    /// Create an empty spool.
    ///
    /// - Throws: If the directory or first segment can't be created or opened, or the volume is low on space.
    init() throws {
        try FileManager.default.createDirectory(at: Self.directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let first = try Self.makeSegment()
        segments = [first]
        writer = try FileHandle(forWritingTo: first)
        reader = try FileHandle(forReadingFrom: first)
    }

    deinit {
        try? writer.close()
        try? reader.close()
        segments.forEach { try? FileManager.default.removeItem(at: $0) }
    }

    /// Remove spool files left behind by a previous run of the Security Extension.
    static func removeLeftovers() {
        try? FileManager.default.removeItem(at: directory)
    }

    /// Create a new, empty, root-only segment file.
    ///
    /// - Returns: The segment's URL.
    /// - Throws: If the volume has less than ``minFreeSpace`` free, or the file can't be created.
    private static func makeSegment() throws -> URL {
        let free = try? directory.resourceValues(forKeys: [.volumeAvailableCapacityKey]).volumeAvailableCapacity
        /// Unknown free space doesn't stop spooling; a failed write still would.
        guard free.map({ Int64($0) >= minFreeSpace }) ?? true else {
            throw CocoaError(.fileWriteOutOfSpace, userInfo: [NSFilePathErrorKey: directory.path])
        }
        let url = directory.appendingPathComponent(UUID().uuidString)
        guard FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
        }
        return url
    }

    /// Append one event to the end of the spool, starting a new segment first if the current one is full.
    ///
    /// - Parameter event: A JSON serialization of `Message`.
    /// - Throws: If the spool is full (see ``maxSize`` and ``minFreeSpace``) or the write fails.
    func append(_ event: Data) throws {
        let recordSize = UInt64(MemoryLayout<UInt32>.size + event.count)
        guard size + recordSize <= Self.maxSize else {
            throw CocoaError(.fileWriteOutOfSpace, userInfo: [NSFilePathErrorKey: Self.directory.path])
        }
        if writerOffset >= Self.segmentSize {
            let next = try Self.makeSegment()
            let nextWriter = try FileHandle(forWritingTo: next)
            try? writer.close()
            segments.append(next)
            writer = nextWriter
            writerOffset = 0
        }

        var length = UInt32(event.count).littleEndian
        var record = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        record.append(event)
        do {
            try writer.write(contentsOf: record)
        } catch {
            /// A partial write (e.g. the disk filled up mid-record) would break the framing for every later record. Cut the
            /// segment back to the last whole record so only this event is lost.
            try? writer.truncate(atOffset: writerOffset)
            throw error
        }
        writerOffset += UInt64(record.count)
        size += recordSize
        count += 1
    }

    /// Read up to `limit` events from the front of the spool, deleting each segment once it's been read.
    ///
    /// - Parameter limit: The most events to return.
    /// - Returns: The oldest unread events, in order.
    /// - Throws: If a read fails or a record is truncated.
    func read(upTo limit: Int) throws -> [Data] {
        var events: [Data] = []
        while events.count < limit, count > 0 {
            guard let header = try reader.read(upToCount: MemoryLayout<UInt32>.size), !header.isEmpty else {
                /// End of this segment. Records never span segments, so move on to the next one.
                try advanceReader()
                continue
            }
            guard header.count == MemoryLayout<UInt32>.size else { throw corrupt() }
            let length = Int(UInt32(littleEndian: header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
            guard let event = try reader.read(upToCount: length), event.count == length else { throw corrupt() }
            events.append(event)
            size -= UInt64(header.count + length)
            count -= 1
        }
        return events
    }

    /// Delete the fully-read oldest segment and start reading the next one.
    ///
    /// - Throws: If there is no next segment while events are still owed (a corrupt spool) or it can't be opened.
    private func advanceReader() throws {
        guard segments.count > 1 else { throw corrupt() }
        let next = try FileHandle(forReadingFrom: segments[1])
        try? reader.close()
        try? FileManager.default.removeItem(at: segments.removeFirst())
        reader = next
    }

    /// - Returns: The error for a spool whose contents don't match what was written.
    private func corrupt() -> CocoaError {
        CocoaError(.fileReadCorruptFile, userInfo: [NSFilePathErrorKey: segments.first?.path ?? Self.directory.path])
    }
}
