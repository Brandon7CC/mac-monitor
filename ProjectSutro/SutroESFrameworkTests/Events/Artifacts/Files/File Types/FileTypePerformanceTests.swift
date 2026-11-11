//
//  FileTypePerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/6/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - File types on a capture lane
/// Times what naming an mmap's file type costs a capture lane: a miss, which sets the read's I/O policies, opens a
/// copy of `/bin/ls`, checks it's the event's and readable, and reads its first 4 KB and its slice's header, and a hit
/// in the lane's ``FileTypeMemory``, which reads nothing. And what setting and putting back the policies alone costs
/// (``ReadingThreadPolicy/whileReading(_:)``).
///
/// The copy is in a temporary folder, read again and again, so it's in the buffer cache: these are the system call
/// costs, not the disk's.
final class FileTypePerformanceTests: PerformanceTestCase {
    /// A copy of `/bin/ls`, and its stat.
    ///
    /// - Returns: The copy's path and stat.
    /// - Throws: The error copying it.
    private func executable() throws -> (path: String, info: stat) {
        let path = try temporaryCopy(of: "/bin/ls")
        return (path, try fileStat(path))
    }

    /// Read a file's type again and again, with no memory.
    ///
    /// - Parameters:
    ///   - name: The case, in the benchmark's name.
    ///   - reader: Who it's read for.
    /// - Throws: ``BenchmarkFailure`` if it isn't an executable, or the error copying it or writing the results.
    private func benchmarkMiss(_ name: String, for reader: FileReader) throws {
        let (path, info) = try executable()
        let volumes = LocalVolumes()
        let reads = 5_000
        try benchmark("enrich.file_type.\(name)", unit: "file", operations: reads) {
            for _ in 0..<reads where FileTypeReader.fileType(at: path, stat: info, for: reader,
                                                              volumes: volumes)?.machOType != "MH_EXECUTE" {
                throw BenchmarkFailure("\(path) isn't an executable")
            }
        }
    }

    /// A miss for this user, who must be able to search every folder above the file, as most mapping processes are.
    func testMiss() throws { try benchmarkMiss("miss", for: currentReader) }
    /// A miss for root, whose reads the identity check passes without looking.
    func testMissForRoot() throws { try benchmarkMiss("miss.root", for: FileReader(uid: 0, gid: 0)) }

    /// Setting a read's two I/O policies and putting them back, around no read: six system calls.
    func testReadingPolicy() throws {
        let reads = 200_000
        var count = 0
        try benchmark("enrich.reading_policy", unit: "read", operations: reads) {
            for _ in 0..<reads { ReadingThreadPolicy.whileReading { count &+= 1 } }
        }
        XCTAssertGreaterThan(count, 0)
    }

    /// A file the lane's memory has: its stat is the key, and nothing is read.
    func testHit() throws {
        let (path, info) = try executable()
        let memory = FileTypeMemory()
        let reader = currentReader
        _ = memory.mappedFileType(at: path, stat: info, for: reader)
        let lookups = 200_000
        try benchmark("enrich.file_type.hit", unit: "file", operations: lookups) {
            for _ in 0..<lookups where memory.mappedFileType(at: path, stat: info, for: reader) == nil {
                throw BenchmarkFailure("\(path) isn't remembered")
            }
        }
    }

    /// A rename of a file its close just read: the close's type, by the rename's stat of the file, and nothing read.
    /// Most renames are a safe save's or a staged file's, which follow their close.
    func testRenameAfterItsClose() throws {
        let (path, info) = try executable()
        let memory = FileTypeMemory()
        let reader = currentReader
        _ = memory.closedFileType(at: path, stat: info, for: reader)
        let lookups = 200_000
        try benchmark("enrich.file_type.rename.hit", unit: "file", operations: lookups) {
            for _ in 0..<lookups where memory.renamedFileType(at: path, stat: info, for: reader) == nil {
                throw BenchmarkFailure("\(path)'s close isn't remembered")
            }
        }
    }
}
