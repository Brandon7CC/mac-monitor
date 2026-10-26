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
    
    // MARK: Records
    
    /// An object whose strings hold braces, brackets, and escaped quotes.
    private static let quoted = #"{"s":"}{ ][ \"quoted\" \\","t":1}"#
    /// Two pretty-printed objects, as Mac Monitor's pretty export writes them.
    private static let pretty = ("{\n  \"a\" : 1,\n  \"b\" : {\n    \"c\" : [\n      1\n    ]\n  }\n}",
                                 "{\n  \"d\" : \"}{\"\n}")
    /// Two objects as an encoder that doesn't indent (Python's `indent=0`) writes them.
    private static let unindented = ("{\n\"a\": [\n{\n\"x\": 1\n},\n{\n\"y\": 2\n}\n]\n}", "{\n\"b\": 2\n}")
    /// The timestamp and process `log show`'s text styles write before each message.
    private static let logPrefix = "2026-10-04 00:01:54.394 Df eslogger[1:2] "
    
    /// Each file's text and the records read from it, with what the case pins.
    private static let files: [(label: String, text: String, records: [Read])] = [
        // JSON Lines
        ("One compact object per line, each numbered by its line", "{\"a\":1}\n{\"b\":{\"c\":[1,2]}}\n",
         [.object("{\"a\":1}", line: 1), .object("{\"b\":{\"c\":[1,2]}}", line: 2)]),
        ("Blank lines, carriage returns, and a missing final newline don't make records",
         "\n{\"a\":1}\r\n\r\n{\"b\":2}", [.object("{\"a\":1}", line: 2), .object("{\"b\":2}", line: 4)]),
        ("Braces, brackets, and escaped quotes inside strings don't end or start an object", quoted + "\n",
         [.object(quoted, line: 1)]),
        // Pretty-printed objects
        ("Pretty-printed objects joined by \"\\n\" (Mac Monitor's pretty export): nested objects are indented, so only "
         + "a top-level object starts at the start of a line", pretty.0 + "\n" + pretty.1 + "\n",
         [.object(pretty.0, line: 1), .object(pretty.1, line: 9)]),
        // JSON arrays
        ("A compact JSON array's elements are its records", "[{\"a\":1},{\"b\":[{\"c\":2}]}]",
         [.object("{\"a\":1}", line: 1), .object("{\"b\":[{\"c\":2}]}", line: 1)]),
        ("A pretty-printed JSON array's elements are indented objects",
         "[\n  {\n    \"a\" : 1\n  },\n  {\n    \"b\" : 2\n  }\n]\n",
         [.object("{\n    \"a\" : 1\n  }", line: 2), .object("{\n    \"b\" : 2\n  }", line: 5)]),
        ("An encoder that doesn't indent starts nested array elements at the start of a line too: inside an array in "
         + "a JSON array file, such a `{` continues the record", "[\n" + unindented.0 + ",\n" + unindented.1 + "\n]\n",
         [.object(unindented.0, line: 2), .object(unindented.1, line: 12)]),
        // Records cut short
        ("A record cut short is skipped when the next one starts at the start of a line, so it doesn't swallow it",
         "{\"a\":1}\n{\"b\":{\"c\":\n{\"d\":4}\n",
         [.object("{\"a\":1}", line: 1), .malformed(line: 2), .object("{\"d\":4}", line: 3)]),
        ("A record cut inside a string ends with its line: a raw newline can't occur in a JSON string",
         "{\"s\":\"cut\n{\"d\":4}\n", [.malformed(line: 1), .object("{\"d\":4}", line: 2)]),
        ("A file that ends inside a record ends with a malformed record", "{\"a\":1}\n{\"b\":[1,",
         [.object("{\"a\":1}", line: 1), .malformed(line: 2)]),
        ("A line of text without an object is a malformed record", "not json\n{\"a\":1}\n",
         [.malformed(line: 1), .object("{\"a\":1}", line: 2)]),
        ("A trailing line of text without an object is a malformed record", "{\"a\":1}\ntrailing text",
         [.object("{\"a\":1}", line: 1), .malformed(line: 2)]),
        // Text logs
        ("`log show`'s text styles write a timestamp and process before each message: that prefix is dropped",
         logPrefix + "{\"a\":1}\n" + logPrefix + "{\"b\":2}\n",
         [.object("{\"a\":1}", line: 1), .object("{\"b\":2}", line: 2)]),
        ("In a text log every message is on one line, so a message the unified log cut short ends with its line",
         "prefix {\"a\":{\"b\":1,\nprefix {\"c\":3}\n", [.malformed(line: 1), .object("{\"c\":3}", line: 2)]),
        // File handling
        ("A UTF-8 byte order mark isn't part of the first record", "\u{FEFF}{\"a\":1}\n",
         [.object("{\"a\":1}", line: 1)]),
        ("An empty file has no records", "", []),
        ("A file of blank lines has no records", "\n  \n", []),
    ]
    
    /// Each file of ``files`` reads as its records.
    func testRecords() {
        for (label, text, expected) in Self.files { XCTAssertEqual(try records(in: text), expected, label) }
    }
    
    // MARK: File handling
    
    /// Only the first `limit` bytes are read: the file is taken to end there.
    func testLimitEndsTheFile() throws {
        let url = try temporaryFile(containing: "{\"a\":1}\n{\"b\":2}\n")
        XCTAssertEqual(try records(in: url, limit: 8), [.object("{\"a\":1}", line: 1)])
        XCTAssertEqual(try records(in: url, limit: 12), [.object("{\"a\":1}", line: 1), .malformed(line: 2)])
    }
    
    /// A record longer than a chunk is read whole, across chunks.
    func testRecordSpanningChunks() throws {
        let long = "{\"s\":\"" + String(repeating: "x", count: TraceRecordReader.chunkSize + 10) + "\"}"
        let reads = try records(in: long + "\n{\"a\":1}\n")
        XCTAssertEqual(reads.count, 2)
        XCTAssertEqual(reads.first, .object(long, line: 1))
        XCTAssertEqual(reads.last, .object("{\"a\":1}", line: 2))
    }
    
    /// The reader reports the file's size and how far it has read.
    func testProgress() throws {
        let reader = try TraceRecordReader(url: try temporaryFile(containing: "{\"a\":1}\n{\"b\":2}\n"))
        XCTAssertEqual(reader.totalBytes, 16)
        _ = try reader.next()
        XCTAssertEqual(reader.bytesRead, 7)
        while try reader.next() != nil {}
        XCTAssertEqual(reader.bytesRead, 16)
    }
    
    /// A folder isn't a trace: reading it could block forever.
    func testFolderIsNotAFile() throws {
        XCTAssertThrowsError(try TraceRecordReader(url: try makeTemporaryDirectory())) { error in
            XCTAssertEqual(error as? TraceImporter.Failure, .notAFile, "\(error)")
        }
    }
}
