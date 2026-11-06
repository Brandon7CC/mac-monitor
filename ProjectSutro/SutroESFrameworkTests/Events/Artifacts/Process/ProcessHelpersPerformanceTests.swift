//
//  ProcessHelpersPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Enrichment on a capture lane
/// Times the file system reads Mac Monitor's enrichment makes while a capture lane builds an event: File Quarantine
/// (every create and rename, and every exec's checks), a script's or plist's contents (an interpreter's exec, a launch
/// item), and a file's first 4 KB, the read a file type check of an mmap or a modified close would make.
///
/// The files are in a temporary folder, read again and again, so they're in the buffer cache: these are the system
/// call costs, not the disk's.
final class ProcessHelpersPerformanceTests: PerformanceTestCase {
    /// The quarantine value Safari writes, as `xattr -p com.apple.quarantine` shows it.
    private static let quarantine = "0083;66ff0000;Safari;"
    
    /// A file in a temporary folder.
    ///
    /// - Parameters:
    ///   - size: Its size: that many bytes of a shell script's text.
    ///   - quarantined: Give it a `com.apple.quarantine` extended attribute?
    /// - Returns: Its path.
    /// - Throws: The error writing it, or the `POSIXError` setting the attribute.
    private func file(size: Int, quarantined: Bool = false) throws -> String {
        let line = "echo 'Mac Monitor'\n"
        let text = "#!/bin/zsh\n" + String(repeating: line, count: size / line.utf8.count + 1)
        let url = try temporaryFile(containing: String(text.utf8.prefix(size))!, named: "script.sh")
        if quarantined {
            let result = Self.quarantine.withCString {
                setxattr(url.path, "com.apple.quarantine", $0, strlen($0), 0, 0)
            }
            if result != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        }
        return url.path
    }
    
    /// Check File Quarantine on one path, again and again.
    ///
    /// - Parameters:
    ///   - name: The case, in the benchmark's name.
    ///   - path: The path.
    ///   - expected: What ``ProcessHelpers/isFileQuarantined(filePath:)`` must answer.
    /// - Throws: ``BenchmarkFailure`` for another answer, or the error writing the results.
    private func benchmarkQuarantine(_ name: String, _ path: String, expected: Int) throws {
        let checks = 20_000
        try benchmark("enrich.quarantine.\(name)", unit: "file", operations: checks) {
            for _ in 0..<checks where ProcessHelpers.isFileQuarantined(filePath: path) != expected {
                throw BenchmarkFailure("\(path) isn't \(expected)")
            }
        }
    }
    
    /// Read a file's text with ``ProcessHelpers/getFileContents(at:)``.
    ///
    /// - Parameters:
    ///   - name: The case, in the benchmark's name.
    ///   - size: The file's size.
    ///   - reads: Reads per sample.
    /// - Throws: ``BenchmarkFailure`` if it isn't read, or the error writing the file or the results.
    private func benchmarkContents(_ name: String, size: Int, reads: Int) throws {
        let path = try file(size: size)
        try benchmark("enrich.file_contents.\(name)", unit: "file", operations: reads) {
            for _ in 0..<reads where ProcessHelpers.getFileContents(at: path) == nil {
                throw BenchmarkFailure("\(path) wasn't read")
            }
        }
    }
    
    func testQuarantineOfAFileWithout() throws { try benchmarkQuarantine("none", try file(size: 64), expected: 0) }
    func testQuarantineOfAQuarantinedFile() throws {
        try benchmarkQuarantine("quarantined", try file(size: 64, quarantined: true), expected: 1)
    }
    func testQuarantineOfAMissingFile() throws {
        try benchmarkQuarantine("missing", NSTemporaryDirectory() + "SutroESFrameworkTests-missing", expected: 2)
    }
    
    func testContentsOfAScript() throws { try benchmarkContents("4k", size: 4_096, reads: 5_000) }
    func testContentsCutAtTheLimit() throws {
        try benchmarkContents("limit", size: ProcessHelpers.fileContentsLimit * 2, reads: 50)
    }
    
    /// A file's first 4 KB, opened as enrichment opens a file (``ProcessHelpers/openRegularFile(at:)``).
    func testHeaderOfAFile() throws {
        let path = try file(size: 1 << 20)
        let reads = 5_000
        try benchmark("enrich.file_header.4k", unit: "file", operations: reads) {
            for _ in 0..<reads {
                guard let file = ProcessHelpers.openRegularFile(at: path),
                      try file.read(upToCount: 4_096)?.count == 4_096 else { throw BenchmarkFailure("\(path) unread") }
            }
        }
    }
}
