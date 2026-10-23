//
//  EventSpoolTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/22/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The event spool
/// Pins the Security Extension's on-disk spool: order across segments, its bounds, its permissions, cleanup, and what
/// a failed read keeps.
final class EventSpoolTests: XCTestCase {
    /// A spool directory of the test's own.
    private var directory: URL!

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("EventSpoolTests-\(UUID().uuidString)", isDirectory: true)
        addTeardownBlock { [directory] in try? FileManager.default.removeItem(at: directory!) }
    }

    /// A spool in the test's directory.
    ///
    /// - Parameters:
    ///   - segmentSize: Start a new segment past this many bytes. 1 puts each event in a segment of its own.
    ///   - maxSize: The most unread bytes.
    ///   - minFreeSpace: The free space to leave.
    /// - Returns: The spool.
    /// - Throws: The spool's error.
    private func spool(segmentSize: UInt64 = 1, maxSize: UInt64 = 1 << 20,
                       minFreeSpace: Int64 = 0) throws -> EventSpool {
        try EventSpool(.init(directory: directory, segmentSize: segmentSize, maxSize: maxSize,
                             minFreeSpace: minFreeSpace))
    }

    /// Events named `0` to `count - 1`.
    ///
    /// - Parameter count: How many.
    /// - Returns: The events.
    private func events(_ count: Int) -> [Data] {
        (0..<count).map { Data("event \($0)".utf8) }
    }

    /// The spool directory's files.
    private var files: [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
    }

    /// Events come back in order across segments, each segment is deleted once read, and nothing is left after.
    func testEventsComeBackInOrderAndSegmentsAreDeletedAsRead() throws {
        var spool: EventSpool? = try self.spool()
        try events(10).forEach { try spool?.append($0) }
        XCTAssertEqual(spool?.count, 10)
        XCTAssertEqual(files.count, 10)

        var read: [Data] = []
        while let batch = try spool?.read(upTo: 3), !batch.isEmpty {
            read += batch
            XCTAssertLessThanOrEqual(files.count, 10 - read.count + 1, "Read segments are deleted")
        }
        XCTAssertEqual(read, events(10))
        XCTAssertEqual(spool?.count, 0)
        XCTAssertEqual(spool?.size, 0)
        spool = nil
        XCTAssertEqual(files, [])
    }

    /// A full spool refuses an event and changes nothing.
    func testAFullSpoolRefusesAnEvent() throws {
        let spool = try spool(segmentSize: 1 << 20, maxSize: 30)
        try spool.append(Data("event 0".utf8))
        try spool.append(Data("event 1".utf8))
        let (count, size) = (spool.count, spool.size)
        XCTAssertThrowsError(try spool.append(Data("event 2 is too long".utf8))) { error in
            XCTAssertEqual((error as? CocoaError)?.code, .fileWriteOutOfSpace)
        }
        XCTAssertEqual(spool.count, count)
        XCTAssertEqual(spool.size, size)
        XCTAssertEqual(try spool.read(upTo: 10), events(2))
    }

    /// No segment starts on a volume with less than the minimum free space.
    func testALowVolumeRefusesASegment() throws {
        XCTAssertThrowsError(try spool(minFreeSpace: .max)) { error in
            XCTAssertEqual((error as? CocoaError)?.code, .fileWriteOutOfSpace)
        }
    }

    /// The directory is root's alone (when root makes it) and each segment is the owner's alone.
    func testFilesAreTheOwnersAlone() throws {
        let spool = try spool()
        try spool.append(Data("event 0".utf8))
        let directoryMode = try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? Int
        XCTAssertEqual(directoryMode, 0o700)
        for file in spool.segmentFiles {
            let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int
            XCTAssertEqual(mode, 0o600, file.lastPathComponent)
        }
    }

    /// A read that fails partway returns what it read before the failure. The next read throws, and what's left
    /// is still counted, so the batcher counts it as lost.
    func testAFailedReadKeepsWhatItRead() throws {
        let spool = try spool()
        try events(3).forEach { try spool.append($0) }
        let second = try FileHandle(forWritingTo: spool.segmentFiles[1])
        try second.truncate(atOffset: 2)
        try second.close()

        XCTAssertEqual(try spool.read(upTo: 3), events(1))
        XCTAssertEqual(spool.count, 2)
        XCTAssertThrowsError(try spool.read(upTo: 3)) { error in
            XCTAssertEqual((error as? CocoaError)?.code, .fileReadCorruptFile)
        }
    }

    /// Leftovers from an extension that crashed are removed.
    func testLeftoversAreRemoved() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: directory.appendingPathComponent("left").path, contents: Data())
        EventSpool.removeLeftovers(in: directory)
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path))
    }
}
