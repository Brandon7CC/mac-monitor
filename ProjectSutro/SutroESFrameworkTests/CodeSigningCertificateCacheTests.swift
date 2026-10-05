//
//  CodeSigningCertificateCacheTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Code signing certificate cache
/// Pins ``CodeSigningCertificateCache``: a file's certificates are read once and remembered until the file changes,
/// the entry expires, or the table fills up; anything that can't be `stat`ed or read is read again every time.
final class CodeSigningCertificateCacheTests: XCTestCase {
    /// Counts reads, and answers each with a certificate naming the path and how many reads came before.
    private final class Reader {
        private let reads = OSAllocatedUnfairLock(initialState: 0)
        /// What a read returns; `nil` stands for a signature that can't be read.
        var fails = false
        
        /// How many reads there were.
        var count: Int { reads.withLock { $0 } }
        
        /// Read a path's "certificates".
        ///
        /// - Parameter path: The path.
        /// - Returns: One certificate naming the path and the read, or `nil` if ``fails``.
        func read(_ path: String) -> [X509Cert]? {
            let number = reads.withLock { reads in
                reads += 1
                return reads
            }
            return fails ? nil : [X509Cert(summary: path, thumbprint: "read \(number)")]
        }
    }
    
    /// A clock the test moves.
    private final class TestClock {
        /// Now, in nanoseconds.
        var now: UInt64 = 1_000_000_000
    }
    
    private var reader = Reader()
    private var clock = TestClock()
    
    /// A fresh reader and clock for each test.
    override func setUp() {
        super.setUp()
        reader = Reader()
        clock = TestClock()
    }
    
    /// A cache that reads with ``reader`` and tells time with ``clock``.
    ///
    /// - Parameters:
    ///   - lifetime: How long entries are used, in seconds.
    ///   - capacity: How many files to keep.
    /// - Returns: The cache.
    private func makeCache(lifetime: TimeInterval = 600, capacity: Int = 1_024) -> CodeSigningCertificateCache {
        let reader = reader, clock = clock
        return CodeSigningCertificateCache(lifetime: lifetime, capacity: capacity, read: reader.read,
                                           clock: { clock.now })
    }
    
    /// Write a file.
    ///
    /// - Parameters:
    ///   - name: Its name.
    ///   - directory: Its directory.
    ///   - contents: What to write.
    /// - Returns: Its path.
    /// - Throws: The error writing it.
    @discardableResult
    private func write(_ name: String, in directory: URL, _ contents: String) throws -> String {
        let url = directory.appendingPathComponent(name)
        try Data(contents.utf8).write(to: url, options: .atomic)
        return url.path
    }
    
    /// The second lookup of an unchanged file returns the first read's certificates without reading.
    ///
    /// - Throws: The error writing the file.
    func testHitReturnsRememberedCertificates() throws {
        let path = try write("tool", in: try makeTemporaryDirectory(), "binary")
        let cache = makeCache()
        let first = cache.certificates(at: path)
        XCTAssertEqual(cache.certificates(at: path), first)
        XCTAssertEqual(first.map(\.thumbprint), ["read 1"])
        XCTAssertEqual(reader.count, 1)
    }
    
    /// A file rewritten in place (same inode, new size or times) is read again.
    ///
    /// - Throws: The error writing the file.
    func testRewrittenFileIsReadAgain() throws {
        let directory = try makeTemporaryDirectory()
        let path = try write("tool", in: directory, "binary")
        let cache = makeCache()
        _ = cache.certificates(at: path)
        let handle = try XCTUnwrap(FileHandle(forWritingAtPath: path))
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("more".utf8))
        try handle.close()
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 2"])
        let touched = Date(timeIntervalSince1970: 1_000)
        try FileManager.default.setAttributes([.modificationDate: touched], ofItemAtPath: path)
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 3"])
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 3"])
    }
    
    /// A file replaced by another (a new inode) with the same size and modification time is read again.
    ///
    /// - Throws: The error writing the files.
    func testReplacedFileIsReadAgain() throws {
        let directory = try makeTemporaryDirectory()
        let path = try write("tool", in: directory, "binary")
        let date = Date(timeIntervalSince1970: 1_000)
        try FileManager.default.setAttributes([.modificationDate: date], ofItemAtPath: path)
        let cache = makeCache()
        _ = cache.certificates(at: path)
        let replacement = try write("replacement", in: directory, "BINARY")
        try FileManager.default.setAttributes([.modificationDate: date], ofItemAtPath: replacement)
        XCTAssertEqual(rename(replacement, path), 0)
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 2"])
    }
    
    /// An entry is used for its lifetime, then the file is read again.
    ///
    /// - Throws: The error writing the file.
    func testEntriesExpire() throws {
        let path = try write("tool", in: try makeTemporaryDirectory(), "binary")
        let cache = makeCache(lifetime: 10)
        _ = cache.certificates(at: path)
        clock.now += 9_999_999_999
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 1"])
        clock.now += 1
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 2"])
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 2"])
    }
    
    /// At capacity, the table is emptied before the next file is added.
    ///
    /// - Throws: The error writing the files.
    func testTableEmptiesAtCapacity() throws {
        let directory = try makeTemporaryDirectory()
        let paths = try (0..<3).map { try write("tool\($0)", in: directory, "binary") }
        let cache = makeCache(capacity: 2)
        _ = cache.certificates(at: paths[0])
        _ = cache.certificates(at: paths[1])
        XCTAssertEqual(cache.count, 2)
        _ = cache.certificates(at: paths[1])
        XCTAssertEqual(reader.count, 2)
        _ = cache.certificates(at: paths[2])
        XCTAssertEqual(cache.count, 1)
        _ = cache.certificates(at: paths[0])
        XCTAssertEqual(reader.count, 4)
    }
    
    /// A path that can't be `stat`ed is read every time, as before.
    func testMissingFileIsReadEveryTime() {
        let cache = makeCache()
        let path = "/nonexistent/\(UUID().uuidString)"
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 1"])
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 2"])
        XCTAssertEqual(cache.count, 0)
    }
    
    /// A signature that can't be read gives no certificates and isn't remembered, so the next event tries again.
    ///
    /// - Throws: The error writing the file.
    func testFailedReadIsNotRemembered() throws {
        let path = try write("tool", in: try makeTemporaryDirectory(), "binary")
        let cache = makeCache()
        reader.fails = true
        XCTAssertEqual(cache.certificates(at: path), [])
        reader.fails = false
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 2"])
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 2"])
    }
    
    /// Lanes looking up the same files at once all get their certificates.
    ///
    /// - Throws: The error writing the files.
    func testConcurrentLookups() throws {
        let directory = try makeTemporaryDirectory()
        let paths = try (0..<8).map { try write("tool\($0)", in: directory, "binary") }
        let cache = makeCache()
        DispatchQueue.concurrentPerform(iterations: 800) { index in
            let path = paths[index % paths.count]
            XCTAssertEqual(cache.certificates(at: path).first?.summary, path)
        }
        XCTAssertEqual(cache.count, paths.count)
        XCTAssertLessThan(reader.count, 800)
    }
    
    /// Through ``ProcessHelpers``, a real executable's certificates are the ones a fresh read finds, each time as new
    /// values.
    ///
    /// - Throws: An `XCTest` failure if the signature can't be read.
    func testProcessHelpersMatchAFreshRead() throws {
        let fresh = try XCTUnwrap(ProcessHelpers.readCodeSigningCerts(forBinaryAt: "/usr/bin/true"))
        let first = ProcessHelpers.getCodeSigningCerts(forBinaryAt: "/usr/bin/true")
        let second = ProcessHelpers.getCodeSigningCerts(forBinaryAt: "/usr/bin/true")
        XCTAssertFalse(fresh.isEmpty)
        for chain in [first, second] {
            XCTAssertEqual(chain.map(\.summary), fresh.map(\.summary))
            XCTAssertEqual(chain.map(\.thumbprint), fresh.map(\.thumbprint))
        }
        XCTAssertTrue(zip(first, second).allSatisfy { $0.id != $1.id })
        XCTAssertNil(ProcessHelpers.readCodeSigningCerts(forBinaryAt: "/nonexistent/\(UUID().uuidString)"))
    }
}
