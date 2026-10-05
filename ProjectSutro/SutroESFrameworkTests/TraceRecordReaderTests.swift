//
//  TraceRecordReaderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Record reader
/// Pins how ``TraceRecordReader`` splits a trace into its JSON objects: JSON Lines, pretty-printed objects, JSON
/// arrays, text logs, and records cut short.
final class TraceRecordReaderTests: XCTestCase {
    /// A record as the tests compare it: an object's text, or text that isn't one, each with the line it starts on.
    private enum Read: Equatable {
        /// A complete object.
        case object(String, line: Int)
        /// An object cut short, or a line of text without one.
        case malformed(line: Int)
    }
    
    /// Every record in a file.
    ///
    /// - Parameters:
    ///   - url: The file.
    ///   - limit: The most bytes to read.
    /// - Returns: The records, in file order.
    /// - Throws: The error opening or reading the file.
    private func records(in url: URL, limit: Int64 = .max) throws -> [Read] {
        let reader = try TraceRecordReader(url: url, limit: limit)
        var records: [Read] = []
        while let record = try reader.next() {
            switch record {
            case .object(let data, let line): records.append(.object(String(decoding: data, as: UTF8.self), line: line))
            case .malformed(let line): records.append(.malformed(line: line))
            }
        }
        return records
    }
    
    /// Every record in a file holding `text`.
    ///
    /// - Parameter text: The file's contents.
    /// - Returns: The records, in file order.
    /// - Throws: The error writing or reading the file.
    private func records(in text: String) throws -> [Read] {
        try records(in: try temporaryFile(containing: text))
    }
    
    // MARK: JSON Lines
    
    /// One compact object per line, each numbered by its line.
    ///
    /// - Throws: The error writing or reading the trace.
    func testJSONLines() throws {
        XCTAssertEqual(try records(in: "{\"a\":1}\n{\"b\":{\"c\":[1,2]}}\n"),
                       [.object("{\"a\":1}", line: 1), .object("{\"b\":{\"c\":[1,2]}}", line: 2)])
    }
    
    /// Blank lines, carriage returns, and a missing final newline don't make records.
    ///
    /// - Throws: The error writing or reading the trace.
    func testJSONLinesWithBlankLinesAndCRLF() throws {
        XCTAssertEqual(try records(in: "\n{\"a\":1}\r\n\r\n{\"b\":2}"),
                       [.object("{\"a\":1}", line: 2), .object("{\"b\":2}", line: 4)])
    }
    
    /// Braces, brackets, and escaped quotes inside strings don't end or start an object.
    ///
    /// - Throws: The error writing or reading the trace.
    func testStringsHideBracesAndQuotes() throws {
        let object = #"{"s":"}{ ][ \"quoted\" \\","t":1}"#
        XCTAssertEqual(try records(in: object + "\n"), [.object(object, line: 1)])
    }
    
    /// The fixtures are read as the tools wrote them: one eslogger line, slashes escaped.
    ///
    /// - Throws: The error writing or reading the trace.
    func testEsloggerFixtureIsOneRecord() throws {
        let records = try records(in: try fixtureURL("eslogger-exit.jsonl"))
        XCTAssertEqual(records.count, 1)
        guard case .object(let text, line: 1)? = records.first else { return XCTFail("Expected an object: \(records)") }
        XCTAssertTrue(text.contains(#""path":"\/usr\/libexec\/exampled""#))
    }
    
    // MARK: Pretty-printed objects
    
    /// Pretty-printed objects joined by "\n" (Mac Monitor's pretty export): nested objects are indented, so only a
    /// top-level object starts at the start of a line.
    ///
    /// - Throws: The error writing or reading the trace.
    func testPrettyPrintedObjects() throws {
        let first = "{\n  \"a\" : 1,\n  \"b\" : {\n    \"c\" : [\n      1\n    ]\n  }\n}"
        let second = "{\n  \"d\" : \"}{\"\n}"
        XCTAssertEqual(try records(in: first + "\n" + second + "\n"),
                       [.object(first, line: 1), .object(second, line: 9)])
    }
    
    // MARK: JSON arrays
    
    /// A compact JSON array's elements are its records.
    ///
    /// - Throws: The error writing or reading the trace.
    func testCompactArray() throws {
        XCTAssertEqual(try records(in: "[{\"a\":1},{\"b\":[{\"c\":2}]}]"),
                       [.object("{\"a\":1}", line: 1), .object("{\"b\":[{\"c\":2}]}", line: 1)])
    }
    
    /// A pretty-printed JSON array's elements are indented objects.
    ///
    /// - Throws: The error writing or reading the trace.
    func testPrettyArray() throws {
        let text = "[\n  {\n    \"a\" : 1\n  },\n  {\n    \"b\" : 2\n  }\n]\n"
        XCTAssertEqual(try records(in: text),
                       [.object("{\n    \"a\" : 1\n  }", line: 2), .object("{\n    \"b\" : 2\n  }", line: 5)])
    }
    
    /// An encoder that doesn't indent (Python's `indent=0`) starts nested array elements at the start of a line too:
    /// inside an array in a JSON array file, such a `{` continues the record.
    ///
    /// - Throws: The error writing or reading the trace.
    func testUnindentedArrayKeepsNestedArrayElements() throws {
        let first = "{\n\"a\": [\n{\n\"x\": 1\n},\n{\n\"y\": 2\n}\n]\n}"
        let second = "{\n\"b\": 2\n}"
        XCTAssertEqual(try records(in: "[\n" + first + ",\n" + second + "\n]\n"),
                       [.object(first, line: 2), .object(second, line: 12)])
    }
    
    // MARK: Records cut short
    
    /// A record cut short is skipped when the next one starts at the start of a line, so it doesn't swallow it.
    ///
    /// - Throws: The error writing or reading the trace.
    func testTruncatedRecordIsSkippedAtTheNextRecord() throws {
        XCTAssertEqual(try records(in: "{\"a\":1}\n{\"b\":{\"c\":\n{\"d\":4}\n"),
                       [.object("{\"a\":1}", line: 1), .malformed(line: 2), .object("{\"d\":4}", line: 3)])
    }
    
    /// A record cut inside a string ends with its line: a raw newline can't occur in a JSON string.
    ///
    /// - Throws: The error writing or reading the trace.
    func testTruncatedStringEndsWithItsLine() throws {
        XCTAssertEqual(try records(in: "{\"s\":\"cut\n{\"d\":4}\n"),
                       [.malformed(line: 1), .object("{\"d\":4}", line: 2)])
    }
    
    /// A file that ends inside a record ends with a malformed record.
    ///
    /// - Throws: The error writing or reading the trace.
    func testFileEndingInsideARecord() throws {
        XCTAssertEqual(try records(in: "{\"a\":1}\n{\"b\":[1,"), [.object("{\"a\":1}", line: 1), .malformed(line: 2)])
    }
    
    /// A line of text without an object is a malformed record.
    ///
    /// - Throws: The error writing or reading the trace.
    func testTextLineIsMalformed() throws {
        XCTAssertEqual(try records(in: "not json\n{\"a\":1}\n"), [.malformed(line: 1), .object("{\"a\":1}", line: 2)])
        XCTAssertEqual(try records(in: "{\"a\":1}\ntrailing text"),
                       [.object("{\"a\":1}", line: 1), .malformed(line: 2)])
    }
    
    // MARK: Text logs
    
    /// `log show`'s text styles write a timestamp and process before each message: that prefix is dropped.
    ///
    /// - Throws: The error writing or reading the trace.
    func testTextLogPrefixIsDropped() throws {
        let prefix = "2026-10-04 00:01:54.394 Df eslogger[1:2] "
        let text = prefix + "{\"a\":1}\n" + prefix + "{\"b\":2}\n"
        XCTAssertEqual(try records(in: text), [.object("{\"a\":1}", line: 1), .object("{\"b\":2}", line: 2)])
    }
    
    /// In a text log every message is on one line, so a message the unified log cut short ends with its line.
    ///
    /// - Throws: The error writing or reading the trace.
    func testTextLogCutMessageEndsWithItsLine() throws {
        let text = "prefix {\"a\":{\"b\":1,\nprefix {\"c\":3}\n"
        XCTAssertEqual(try records(in: text), [.malformed(line: 1), .object("{\"c\":3}", line: 2)])
    }
    
    // MARK: File handling
    
    /// A UTF-8 byte order mark isn't part of the first record.
    ///
    /// - Throws: The error writing or reading the trace.
    func testByteOrderMarkIsDropped() throws {
        XCTAssertEqual(try records(in: "\u{FEFF}{\"a\":1}\n"), [.object("{\"a\":1}", line: 1)])
    }
    
    /// Only the first `limit` bytes are read: the file is taken to end there.
    ///
    /// - Throws: The error writing or reading the trace.
    func testLimitEndsTheFile() throws {
        let url = try temporaryFile(containing: "{\"a\":1}\n{\"b\":2}\n")
        XCTAssertEqual(try records(in: url, limit: 8), [.object("{\"a\":1}", line: 1)])
        XCTAssertEqual(try records(in: url, limit: 12), [.object("{\"a\":1}", line: 1), .malformed(line: 2)])
    }
    
    /// A record longer than a chunk is read whole, across chunks.
    ///
    /// - Throws: The error writing or reading the trace.
    func testRecordSpanningChunks() throws {
        let long = "{\"s\":\"" + String(repeating: "x", count: TraceRecordReader.chunkSize + 10) + "\"}"
        let reads = try records(in: long + "\n{\"a\":1}\n")
        XCTAssertEqual(reads.count, 2)
        XCTAssertEqual(reads.first, .object(long, line: 1))
        XCTAssertEqual(reads.last, .object("{\"a\":1}", line: 2))
    }
    
    /// The reader reports the file's size and how far it has read.
    ///
    /// - Throws: The error writing or reading the trace.
    func testProgress() throws {
        let reader = try TraceRecordReader(url: try temporaryFile(containing: "{\"a\":1}\n{\"b\":2}\n"))
        XCTAssertEqual(reader.totalBytes, 16)
        _ = try reader.next()
        XCTAssertEqual(reader.bytesRead, 7)
        while try reader.next() != nil {}
        XCTAssertEqual(reader.bytesRead, 16)
    }
    
    /// An empty file has no records.
    ///
    /// - Throws: The error writing or reading the trace.
    func testEmptyFile() throws {
        XCTAssertEqual(try records(in: ""), [])
        XCTAssertEqual(try records(in: "\n  \n"), [])
    }
    
    /// A folder isn't a trace: reading it could block forever.
    ///
    /// - Throws: The error writing or reading the trace.
    func testFolderIsNotAFile() throws {
        XCTAssertThrowsError(try TraceRecordReader(url: try makeTemporaryDirectory())) { error in
            guard case TraceImporter.Failure.notAFile = error else { return XCTFail("Unexpected error: \(error)") }
        }
    }
}
