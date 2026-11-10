//
//  FileTypeClassifierPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/9/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Classifying sampled bytes
/// Times what naming bytes already read costs a capture lane (``FileTypeClassifier``), with no I/O: 4 KB of each
/// kind of content the classifier walks furthest for, and a trailer's check. What a read adds is
/// `enrich.file_type.miss`'s.
///
/// | Benchmark | What it classifies |
/// |---|---|
/// | `enrich.file_type.classify.data` | 4 KB of random bytes: every signature is tried, then the text check fails |
/// | `enrich.file_type.classify.raw` | A raw GPT disk's first 4 KB, as a read/write disk image starts |
/// | `enrich.file_type.classify.fat` | A FAT32 volume after an MBR, the last raw disk checked at 510 |
/// | `enrich.file_type.classify.text` | 4 KB of text: every signature is tried, then all of it is decoded |
/// | `enrich.file_type.classify.plist` | A 4 KB XML property list, searched for its marks |
/// | `enrich.file_type.classify.binary-plist` | A 4 KB binary property list, searched for a sparse bundle's kind |
/// | `enrich.file_type.classify.trailer` | Random bytes, then a trailer of data, as an image's end is checked |
final class FileTypeClassifierPerformanceTests: PerformanceTestCase {
    /// Classifications per sample.
    private static let classifications = 20_000

    /// Classify one header again and again.
    ///
    /// - Parameters:
    ///   - name: The case, in the benchmark's name.
    ///   - header: The file's first bytes.
    ///   - trailer: The file's last 512 bytes, or `nil` to check the header alone.
    ///   - expected: The identifier it must be named by, so the benchmark times the path it names.
    /// - Throws: ``BenchmarkFailure`` if it's named otherwise, or the error writing the results.
    private func benchmarkClassify(_ name: String, _ header: [UInt8], trailer: [UInt8]? = nil,
                                   expecting expected: String) throws {
        let named = FileTypeClassifier.classify(header: header, slice: nil, trailer: trailer).identifier
        guard named == expected else { throw BenchmarkFailure("\(name) is \(named), not \(expected)") }
        try benchmark("enrich.file_type.classify.\(name)", unit: "file", operations: Self.classifications) {
            for _ in 0..<Self.classifications
            where FileTypeClassifier.classify(header: header, slice: nil, trailer: trailer).identifier != expected {
                throw BenchmarkFailure("\(name) isn't \(expected)")
            }
        }
    }

    /// Bytes from a fixed seed, so every run classifies the same ones.
    ///
    /// - Parameter count: How many.
    /// - Returns: The bytes.
    private static func noise(_ count: Int) -> [UInt8] {
        var state: UInt64 = 0x9E37_79B9_7F4A_7C15
        return (0..<count).map { _ in
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return UInt8(truncatingIfNeeded: state >> 56)
        }
    }

    /// Random bytes that aren't text, and don't start with any signature.
    private static let data: [UInt8] = [0x00, 0x7E] + noise(FileTypeClassifier.headerLength - 2)

    /// Random bytes.
    func testData() throws { try benchmarkClassify("data", Self.data, expecting: "public.data") }

    /// A raw disk with a GPT: a protective MBR's signature at 510, the GPT header at 512, then zeros.
    func testRawDisk() throws {
        var header = [UInt8](repeating: 0, count: FileTypeClassifier.headerLength)
        header.replaceSubrange(510..<520, with: [0x55, 0xAA] + Array("EFI PART".utf8))
        try benchmarkClassify("raw", header, expecting: "com.apple.disk-image-raw")
    }

    /// A FAT32 volume after an MBR: the MBR's signature at 510, then the boot sector's name at 594 and its signature
    /// at 1022, so the GPT and the boot sector at 0 are checked first.
    func testFATVolume() throws {
        var header = [UInt8](repeating: 0, count: FileTypeClassifier.headerLength)
        header.replaceSubrange(510..<512, with: [0x55, 0xAA])
        header.replaceSubrange(594..<602, with: Array("FAT32   ".utf8))
        header.replaceSubrange(1_022..<1_024, with: [0x55, 0xAA])
        try benchmarkClassify("fat", header, expecting: "com.apple.disk-image-raw")
    }

    /// Text, all of it decoded.
    func testText() throws {
        let line = Array("The quick brown fox jumps over the lazy dog, again and again.\n".utf8)
        let text = Array((0..<(FileTypeClassifier.headerLength / line.count + 1)).flatMap { _ in line }
            .prefix(FileTypeClassifier.headerLength))
        try benchmarkClassify("text", text, expecting: "public.plain-text")
    }

    /// An XML property list of 4 KB, with no mark but its DOCTYPE and root element.
    func testPropertyList() throws {
        let entries = (0..<100).map { "\t<key>Key\($0)</key>\n\t<string>Value \($0)</string>\n" }.joined()
        let plist = #"<?xml version="1.0" encoding="UTF-8"?>"# + "\n"
            + #"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/"#
            + #"PropertyList-1.0.dtd">"# + "\n<plist version=\"1.0\">\n<dict>\n" + entries
        let header = Array(Array(plist.utf8).prefix(FileTypeClassifier.headerLength))
        XCTAssertEqual(header.count, FileTypeClassifier.headerLength)
        try benchmarkClassify("plist", header, expecting: "com.apple.xml-property-list")
    }

    /// A binary property list of 4 KB that isn't a sparse bundle's, searched whole for its kind.
    func testBinaryPropertyList() throws {
        let plist = Dictionary(uniqueKeysWithValues: (0..<300).map { ("Key\($0)", "Value \($0)") })
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .binary, options: 0)
        let header = Array(Array(data).prefix(FileTypeClassifier.headerLength))
        XCTAssertEqual(header.count, FileTypeClassifier.headerLength)
        try benchmarkClassify("binary-plist", header, expecting: "com.apple.binary-property-list")
    }

    /// Random bytes and a trailer of random bytes, which isn't an image's.
    func testTrailer() throws {
        try benchmarkClassify("trailer", Self.data, trailer: Self.noise(FileTypeClassifier.trailerLength),
                              expecting: "public.data")
    }
}
