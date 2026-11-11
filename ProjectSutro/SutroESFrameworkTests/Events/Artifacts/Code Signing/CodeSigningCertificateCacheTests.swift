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
/// the entry expires, or the table fills up. Anything that can't be `stat`ed or read is read again every time.
final class CodeSigningCertificateCacheTests: XCTestCase {
    /// Counts reads, and answers each with a certificate naming the path and how many reads came before.
    private final class Reader {
        private let reads = OSAllocatedUnfairLock(initialState: 0)
        /// What a read returns. `nil` stands for a signature that can't be read.
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
    
    private let reader = Reader()
    private let clock = TestClock()
    
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
    
    /// A file rewritten in place (same inode, new size or times) is read again.
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
    
    /// An event's stat is the file's identity, with no `stat(2)`: the same entry as the path's own stat finds, another
    /// for a stat that differs, and a path that doesn't exist is still remembered. A stat naming no file is ignored.
    func testAnEventsStatIsTheIdentity() throws {
        let path = try write("tool", in: try makeTemporaryDirectory(), "binary")
        var info = stat()
        XCTAssertEqual(stat(path, &info), 0)
        let cache = makeCache()
        XCTAssertEqual(cache.certificates(at: path, stat: Stat(from: info)).map(\.thumbprint), ["read 1"])
        XCTAssertEqual(cache.certificates(at: path).map(\.thumbprint), ["read 1"], "The same file")
        XCTAssertEqual(CodeSigningCertificateCache.FileIdentity(path: path, stat: Stat(from: info)),
                       CodeSigningCertificateCache.FileIdentity(path: path))
        var rewritten = info
        rewritten.st_size += 1
        XCTAssertEqual(cache.certificates(at: path, stat: Stat(from: rewritten)).map(\.thumbprint), ["read 2"])
        XCTAssertEqual(cache.certificates(at: "/no/such/tool", stat: Stat(from: info)).map(\.thumbprint), ["read 3"])
        XCTAssertEqual(cache.certificates(at: "/no/such/tool", stat: Stat(from: info)).map(\.thumbprint), ["read 3"])
        var unnamed = info
        unnamed.st_ino = 0
        XCTAssertEqual(cache.certificates(at: path, stat: Stat(from: unnamed)).map(\.thumbprint), ["read 1"],
                       "Falls back to the path's own stat")
    }

    /// An entry is used for its lifetime, then the file is read again.
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
    
    /// Through ``ProcessHelpers``, a real executable's certificates are the ones a fresh read finds, each time with the
    /// same ids: their thumbprints.
    func testProcessHelpersMatchAFreshRead() throws {
        let fresh = try XCTUnwrap(ProcessHelpers.readCodeSigningCerts(forBinaryAt: "/usr/bin/true"))
        let first = ProcessHelpers.getCodeSigningCerts(forBinaryAt: "/usr/bin/true")
        let second = ProcessHelpers.getCodeSigningCerts(forBinaryAt: "/usr/bin/true")
        XCTAssertFalse(fresh.isEmpty)
        for chain in [first, second] {
            XCTAssertEqual(chain.map(\.summary), fresh.map(\.summary))
            XCTAssertEqual(chain.map(\.thumbprint), fresh.map(\.thumbprint))
        }
        XCTAssertEqual(first.map(\.id), second.map(\.id))
        XCTAssertNil(ProcessHelpers.readCodeSigningCerts(forBinaryAt: "/nonexistent/\(UUID().uuidString)"))
    }

    /// A capture lane's read is the plain read for an ordinary executable and for an app's, and nothing at all, at
    /// once, for an executable in a bundle whose Info.plist is a FIFO: Security opened it and waited for good on
    /// macOS 13, and the lane with it.
    func testALanesReadNeverWaitsInABundle() throws {
        let helpers = ProcessHelpers.self
        XCTAssertEqual(helpers.enclosingBundle(ofExecutableAt: "/A/B.app/Contents/MacOS/b"), "/A/B.app")
        XCTAssertNil(helpers.enclosingBundle(ofExecutableAt: "/usr/bin/true"))
        XCTAssertNil(helpers.enclosingBundle(ofExecutableAt: "/A/B.app/Contents/Helpers/b"))
        for path in ["/usr/bin/true", "/System/Applications/Calculator.app/Contents/MacOS/Calculator"] {
            XCTAssertEqual(helpers.readGuardedCodeSigningCerts(forBinaryAt: path)?.map(\.id),
                           helpers.readCodeSigningCerts(forBinaryAt: path)?.map(\.id), path)
        }
        let bundle = try makeTemporaryDirectory().appendingPathComponent("Fifo.app/Contents", isDirectory: true)
        let executable = bundle.appendingPathComponent("MacOS/Fifo")
        try FileManager.default.createDirectory(at: executable.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: executable.path)
        XCTAssertEqual(mkfifo(bundle.appendingPathComponent("Info.plist").path, 0o644), 0)
        let started = Date()
        XCTAssertNil(helpers.readGuardedCodeSigningCerts(forBinaryAt: executable.path))
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.4, "It waited for its deadline")
    }
}
