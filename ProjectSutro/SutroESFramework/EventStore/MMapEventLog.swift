//
//  MMapEventLog.swift
//  SutroESFramework
//
//  Memory-mapped binary event log, inspired by ProcMon's approach on Windows.
//
//  Layout:
//  ┌──────────────────────────────────────┐
//  │ Header (64 bytes)                    │
//  │  - magic: UInt32 ("MMLG")           │
//  │  - version: UInt32                   │
//  │  - eventCount: UInt64               │
//  │  - dataOffset: UInt64               │
//  │  - reserved: 40 bytes               │
//  ├──────────────────────────────────────┤
//  │ Event Records (variable length)      │
//  │  ┌─────────────────────────────────┐ │
//  │  │ length: UInt32 (of payload)     │ │
//  │  │ payload: [UInt8] (encoded msg)  │ │
//  │  └─────────────────────────────────┘ │
//  │  ... repeated ...                    │
//  └──────────────────────────────────────┘
//

import Foundation
import OSLog

/// A high-performance, memory-mapped append-only log for binary event data.
///
/// Events are stored as length-prefixed blobs encoded via `Codable`.
/// The file is grown in chunks to minimize `ftruncate` calls.
public final class MMapEventLog {
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent", category: "MMapEventLog")

    // MARK: - Header constants
    private static let magic: UInt32 = 0x4D4D4C47 // "MMLG"
    private static let currentVersion: UInt32 = 1
    private static let headerSize: Int = 64
    private static let growthChunkSize: Int = 4 * 1024 * 1024 // 4 MB growth increments
    private static let residentHotWindowSize: Int = 8 * 1024 * 1024
    private static let reclaimMinStepSize: Int = 2 * 1024 * 1024

    // MARK: - File state
    private let fileURL: URL
    private var fileDescriptor: Int32 = -1
    private var mappedPointer: UnsafeMutableRawPointer?
    private var mappedSize: Int = 0

    /// Current write offset (past the header, into the data region)
    private var writeOffset: Int = headerSize

    /// Oldest offset that has not yet been advised as reclaimable.
    private var lastReclaimedOffset: Int = headerSize

    /// Number of events written
    private(set) var eventCount: UInt64 = 0

    /// Serial queue for thread-safe writes
    private let writeQueue = DispatchQueue(label: "com.swiftlydetecting.mmapeventlog.write")

    /// Encoder for serializing events
    private let encoder: PropertyListEncoder = {
        let e = PropertyListEncoder()
        e.outputFormat = .binary
        return e
    }()

    /// Decoder for reading events back
    private let decoder = PropertyListDecoder()

    // MARK: - Init / Deinit

    /// Creates or opens an MMAP event log at the specified URL.
    ///
    /// - Parameter url: File URL for the log. Created if it doesn't exist.
    public init(url: URL) throws {
        self.fileURL = url

        // Ensure parent directory exists
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        // Open or create the file
        fileDescriptor = Darwin.open(url.path, O_RDWR | O_CREAT, 0o644)
        guard fileDescriptor >= 0 else {
            throw MMapError.fileOpenFailed(errno: errno)
        }

        // Get current file size
        var stat = stat()
        fstat(fileDescriptor, &stat)
        let currentSize = Int(stat.st_size)

        if currentSize < MMapEventLog.headerSize {
            // New file — initialize
            try growFile(to: MMapEventLog.growthChunkSize)
            try mapFile()
            writeHeader()
        } else {
            // Existing file — map and read header
            let alignedSize = alignToChunk(currentSize)
            if alignedSize > currentSize {
                try growFile(to: alignedSize)
            }
            try mapFile()
            try readHeader()
        }
    }

    deinit {
        sync()
        if let ptr = mappedPointer, mappedSize > 0 {
            munmap(ptr, mappedSize)
        }
        if fileDescriptor >= 0 {
            Darwin.close(fileDescriptor)
        }
    }

    // MARK: - Public API

    /// Appends an encoded event to the log.
    ///
    /// - Parameter message: The event to append (must be `Codable`).
    /// - Returns: The byte offset where this event was written (for indexing).
    @discardableResult
    public func appendEvent(_ message: Message) throws -> Int {
        let data = try encoder.encode(message)
        return try writeQueue.sync {
            let offset = try appendRaw(data)
            reclaimOldMappedPagesIfNeeded()
            return offset
        }
    }

    /// Appends a batch of events efficiently.
    ///
    /// - Parameter messages: The events to append.
    /// - Returns: Array of (offset, message) tuples.
    @discardableResult
    public func appendEvents(_ messages: [Message]) throws -> [(offset: Int, message: Message)] {
        // Pre-encode all messages
        let encoded: [(Data, Message)] = try messages.map { msg in
            (try encoder.encode(msg), msg)
        }

        return try writeQueue.sync {
            var results: [(Int, Message)] = []
            results.reserveCapacity(encoded.count)

            for (data, msg) in encoded {
                let offset = try appendRaw(data)
                results.append((offset, msg))
            }

            reclaimOldMappedPagesIfNeeded()
            return results
        }
    }

    /// Reads the event at the given byte offset.
    ///
    /// - Parameter offset: The byte offset returned by `appendEvent`.
    /// - Returns: The decoded `Message`.
    public func readEvent(at offset: Int) throws -> Message {
        guard let ptr = mappedPointer else {
            throw MMapError.notMapped
        }
        guard offset >= MMapEventLog.headerSize, offset < writeOffset else {
            throw MMapError.invalidOffset(offset)
        }

        let lengthPtr = ptr.advanced(by: offset)
        let length = lengthPtr.loadUnaligned(as: UInt32.self)
        let payloadOffset = offset + MemoryLayout<UInt32>.size

        guard payloadOffset + Int(length) <= writeOffset else {
            throw MMapError.corruptedRecord(offset: offset)
        }

        let payloadPtr = ptr.advanced(by: payloadOffset)
        let data = Data(bytes: payloadPtr, count: Int(length))
        return try decoder.decode(Message.self, from: data)
    }

    /// Reads all events from the log.
    ///
    /// - Returns: Array of all stored messages.
    public func readAllEvents() throws -> [Message] {
        guard let ptr = mappedPointer else {
            throw MMapError.notMapped
        }

        var messages: [Message] = []
        messages.reserveCapacity(Int(eventCount))

        var offset = MMapEventLog.headerSize
        while offset < writeOffset {
            let lengthPtr = ptr.advanced(by: offset)
            let length = lengthPtr.loadUnaligned(as: UInt32.self)
            let payloadOffset = offset + MemoryLayout<UInt32>.size

            guard payloadOffset + Int(length) <= writeOffset else {
                MMapEventLog.logger.warning("Truncated record at offset \(offset), stopping read.")
                break
            }

            let payloadPtr = ptr.advanced(by: payloadOffset)
            let data = Data(bytes: payloadPtr, count: Int(length))

            do {
                let msg = try decoder.decode(Message.self, from: data)
                messages.append(msg)
            } catch {
                MMapEventLog.logger.error("Failed to decode event at offset \(offset): \(error)")
            }

            offset = payloadOffset + Int(length)
        }

        return messages
    }

    /// Reads all events from the log with their byte offsets.
    ///
    /// - Returns: Array of (offset, message) tuples for index building.
    public func readAllEventsWithOffsets() throws -> [(offset: Int, message: Message)] {
        guard let ptr = mappedPointer else {
            throw MMapError.notMapped
        }

        var results: [(offset: Int, message: Message)] = []
        results.reserveCapacity(Int(eventCount))

        var offset = MMapEventLog.headerSize
        while offset < writeOffset {
            let lengthPtr = ptr.advanced(by: offset)
            let length = lengthPtr.loadUnaligned(as: UInt32.self)
            let payloadOffset = offset + MemoryLayout<UInt32>.size

            guard payloadOffset + Int(length) <= writeOffset else {
                MMapEventLog.logger.warning("Truncated record at offset \(offset), stopping read.")
                break
            }

            let payloadPtr = ptr.advanced(by: payloadOffset)
            let data = Data(bytes: payloadPtr, count: Int(length))

            do {
                let msg = try decoder.decode(Message.self, from: data)
                results.append((offset: offset, message: msg))
            } catch {
                MMapEventLog.logger.error("Failed to decode event at offset \(offset): \(error)")
            }

            offset = payloadOffset + Int(length)
        }

        return results
    }

    /// Resets the log, discarding all events.
    public func reset() throws {
        try writeQueue.sync {
            eventCount = 0
            writeOffset = MMapEventLog.headerSize
            lastReclaimedOffset = MMapEventLog.headerSize
            updateHeaderEventCount()
            updateHeaderWriteOffset()
        }
    }

    /// Flushes dirty pages to disk.
    public func sync() {
        guard let ptr = mappedPointer, mappedSize > 0 else { return }
        msync(ptr, mappedSize, MS_ASYNC)
    }

    /// Returns the currently allocated MMAP file size in bytes.
    public func currentAllocatedSizeBytes() -> Int {
        return writeQueue.sync { mappedSize }
    }

    /// Returns the currently used byte count (header + records).
    public func currentUsedSizeBytes() -> Int {
        return writeQueue.sync { writeOffset }
    }

    // MARK: - Private helpers

    /// Appends raw data (already on the write queue).
    private func appendRaw(_ data: Data) throws -> Int {
        let recordSize = MemoryLayout<UInt32>.size + data.count
        let neededSize = writeOffset + recordSize

        // Grow if necessary
        if neededSize > mappedSize {
            let newSize = alignToChunk(neededSize)
            try remapFile(to: newSize)
        }

        guard let ptr = mappedPointer else {
            throw MMapError.notMapped
        }

        let eventOffset = writeOffset

        // Write length prefix
        var length = UInt32(data.count)
        memcpy(ptr.advanced(by: writeOffset), &length, MemoryLayout<UInt32>.size)
        writeOffset += MemoryLayout<UInt32>.size

        // Write payload
        data.withUnsafeBytes { rawBuffer in
            memcpy(ptr.advanced(by: writeOffset), rawBuffer.baseAddress!, data.count)
        }
        writeOffset += data.count

        eventCount += 1

        // Update header
        updateHeaderEventCount()
        updateHeaderWriteOffset()

        return eventOffset
    }

    private func writeHeader() {
        guard let ptr = mappedPointer else { return }
        var magic = MMapEventLog.magic
        var version = MMapEventLog.currentVersion
        var count: UInt64 = 0
        var dataOffset = UInt64(MMapEventLog.headerSize)

        memcpy(ptr, &magic, 4)
        memcpy(ptr.advanced(by: 4), &version, 4)
        memcpy(ptr.advanced(by: 8), &count, 8)
        memcpy(ptr.advanced(by: 16), &dataOffset, 8)
        // Remaining 40 bytes are reserved (zero-initialized by ftruncate)
    }

    private func readHeader() throws {
        guard let ptr = mappedPointer else {
            throw MMapError.notMapped
        }

        let magic = ptr.loadUnaligned(as: UInt32.self)
        guard magic == MMapEventLog.magic else {
            throw MMapError.invalidMagic(magic)
        }

        let version = ptr.advanced(by: 4).loadUnaligned(as: UInt32.self)
        guard version == MMapEventLog.currentVersion else {
            throw MMapError.unsupportedVersion(version)
        }

        eventCount = ptr.advanced(by: 8).loadUnaligned(as: UInt64.self)
        let dataOffset = ptr.advanced(by: 16).loadUnaligned(as: UInt64.self)

        // Walk the records to find the actual write offset
        writeOffset = Int(dataOffset)
        var recordsFound: UInt64 = 0
        while recordsFound < eventCount && writeOffset < mappedSize {
            let length = ptr.advanced(by: writeOffset).loadUnaligned(as: UInt32.self)
            let nextOffset = writeOffset + MemoryLayout<UInt32>.size + Int(length)
            if nextOffset > mappedSize { break }
            writeOffset = nextOffset
            recordsFound += 1
        }

        if recordsFound != eventCount {
            MMapEventLog.logger.warning("Header claims \(self.eventCount) events but found \(recordsFound). Adjusting.")
            eventCount = recordsFound
            updateHeaderEventCount()
        }
    }

    private func updateHeaderEventCount() {
        guard let ptr = mappedPointer else { return }
        var count = eventCount
        memcpy(ptr.advanced(by: 8), &count, 8)
    }

    private func updateHeaderWriteOffset() {
        guard let ptr = mappedPointer else { return }
        var offset = UInt64(writeOffset)
        memcpy(ptr.advanced(by: 16), &offset, 8)
    }

    private func growFile(to size: Int) throws {
        guard ftruncate(fileDescriptor, off_t(size)) == 0 else {
            throw MMapError.truncateFailed(errno: errno)
        }
    }

    private func mapFile() throws {
        var stat = stat()
        fstat(fileDescriptor, &stat)
        let size = Int(stat.st_size)

        let ptr = mmap(nil, size, PROT_READ | PROT_WRITE, MAP_SHARED, fileDescriptor, 0)
        guard ptr != MAP_FAILED else {
            throw MMapError.mmapFailed(errno: errno)
        }

        mappedPointer = ptr
        mappedSize = size
    }

    private func remapFile(to newSize: Int) throws {
        // Unmap current
        if let ptr = mappedPointer, mappedSize > 0 {
            msync(ptr, mappedSize, MS_SYNC)
            munmap(ptr, mappedSize)
            mappedPointer = nil
        }

        // Grow and remap
        try growFile(to: newSize)
        try mapFile()
    }

    private func alignToChunk(_ size: Int) -> Int {
        let chunk = MMapEventLog.growthChunkSize
        return ((size + chunk - 1) / chunk) * chunk
    }

    private func reclaimOldMappedPagesIfNeeded() {
        guard let ptr = mappedPointer else { return }

        let pageSize = Int(getpagesize())
        let reclaimLimit = writeOffset - MMapEventLog.residentHotWindowSize
        guard reclaimLimit > MMapEventLog.headerSize else { return }

        let targetOffset = (reclaimLimit / pageSize) * pageSize
        guard targetOffset > lastReclaimedOffset else { return }

        let reclaimLength = targetOffset - lastReclaimedOffset
        guard reclaimLength >= MMapEventLog.reclaimMinStepSize else { return }

        let startPtr = ptr.advanced(by: lastReclaimedOffset)
        _ = msync(startPtr, reclaimLength, MS_ASYNC)
        _ = madvise(startPtr, reclaimLength, MADV_DONTNEED)
        lastReclaimedOffset = targetOffset
    }

    // MARK: - Errors

    public enum MMapError: Error, LocalizedError {
        case fileOpenFailed(errno: Int32)
        case truncateFailed(errno: Int32)
        case mmapFailed(errno: Int32)
        case notMapped
        case invalidOffset(Int)
        case corruptedRecord(offset: Int)
        case invalidMagic(UInt32)
        case unsupportedVersion(UInt32)

        public var errorDescription: String? {
            switch self {
            case .fileOpenFailed(let e): return "Failed to open file: \(String(cString: strerror(e)))"
            case .truncateFailed(let e): return "Failed to grow file: \(String(cString: strerror(e)))"
            case .mmapFailed(let e): return "mmap failed: \(String(cString: strerror(e)))"
            case .notMapped: return "File not mapped"
            case .invalidOffset(let o): return "Invalid offset: \(o)"
            case .corruptedRecord(let o): return "Corrupted record at offset: \(o)"
            case .invalidMagic(let m): return "Invalid magic: \(m)"
            case .unsupportedVersion(let v): return "Unsupported version: \(v)"
            }
        }
    }
}
