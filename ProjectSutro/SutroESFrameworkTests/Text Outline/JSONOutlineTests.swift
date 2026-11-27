//
//  JSONOutlineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - JSON outline
/// Pins ``JSONOutline``: each container's brackets, lines, count and key path, each value's ranges, the lookups a JSON
/// view makes, and that malformed or cut-off JSON never traps.
final class JSONOutlineTests: XCTestCase {
    /// Containers and values nest, with key paths that leave out array indexes, and counts of keys and items.
    func testNestingAndKeyPaths() {
        let text = #"{"a": {"b": [1, {"c": true}], "d": null}, "e": "x"}"#
        let outline = JSONOutline(text)
        XCTAssertEqual(outline.containers.map(\.isArray), [false, false, true, false])
        XCTAssertEqual(outline.containers.map(\.count), [2, 2, 2, 1])
        XCTAssertEqual(outline.values.map(\.keyPath), ["", "a", "a.b", "a.b", "a.b", "a.b.c", "a.d", "e"])
        XCTAssertEqual(outline.values.map(\.kind), [.object, .object, .array, .number, .object, .boolean, .null,
                                                    .string])
        XCTAssertEqual(outline.values.map(\.isInArray), [false, false, false, true, true, true, false, false])
        XCTAssertEqual(outline.values.map(\.parent), [nil, 0, 1, 2, 2, 3, 1, 0])
        XCTAssertEqual(outline.values.map(\.container), [0, 1, 2, nil, 3, nil, nil, nil])
        let string = text as NSString
        XCTAssertEqual(outline.values.map { string.substring(with: $0.range) },
                       [text, #"{"b": [1, {"c": true}], "d": null}"#, #"[1, {"c": true}]"#, "1", #"{"c": true}"#,
                        "true", "null", #""x""#])
        XCTAssertEqual(outline.values.map { $0.key.map(string.substring) }, [nil, #""a""#, #""b""#, nil, nil,
                                                                              #""c""#, #""d""#, #""e""#])
        for container in outline.containers {
            XCTAssertEqual(outline.values[container.value].range.location, container.open)
            XCTAssertEqual(container.close.map { $0 + 1 }, NSMaxRange(outline.values[container.value].range))
        }
    }

    /// Brackets' offsets and lines in pretty-printed JSON, and which containers fold.
    func testLinesAndFolding() throws {
        let text = "{\n  \"a\" : [\n    1,\n    2\n  ],\n  \"b\" : {},\n  \"c\" : [ 3 ]\n}"
        let outline = JSONOutline(text)
        XCTAssertEqual(outline.lines, TextLines(text))
        XCTAssertEqual(outline.containers.map(\.startLine), [0, 1, 5, 6])
        XCTAssertEqual(outline.containers.map(\.endLine), [7, 4, 5, 6])
        XCTAssertEqual(outline.containers.map(\.isFoldable), [true, true, false, false])
        XCTAssertEqual(outline.foldable(onLine: 0), 0)
        XCTAssertEqual(outline.foldable(onLine: 1), 1)
        XCTAssertNil(outline.foldable(onLine: 5))
        let string = text as NSString
        for container in outline.containers {
            XCTAssertEqual(string.character(at: container.open), container.isArray ? 0x5B : 0x7B)
            let close = try XCTUnwrap(container.close)
            XCTAssertEqual(string.character(at: close), container.isArray ? 0x5D : 0x7D)
        }
    }

    /// Brackets, colons and commas in strings are text, and escaped quotes don't end a string. Keys are read with
    /// their escapes, and Copy Value unescapes a string.
    func testStringsWithBracketsAndEscapes() {
        let text = #"{"k{": "a]\"}[,:", "\"q\"": "\\", "u]": "é\n", "e": ""}"#
        let outline = JSONOutline(text)
        XCTAssertEqual(outline.containers.count, 1)
        XCTAssertEqual(outline.containers[0].count, 4)
        XCTAssertEqual(outline.values.map(\.keyPath), ["", "k{", "\"q\"", "u]", "e"])
        XCTAssertEqual(outline.values.dropFirst().map(\.kind), [.string, .string, .string, .string])
        let string = text as NSString
        XCTAssertEqual((1..<5).map { outline.copiedText(of: $0, in: string) }, [#"a]"}[,:"#, "\\", "é\n", ""])
        XCTAssertEqual(outline.copiedText(of: 0, in: string), text)
        XCTAssertEqual(outline.containers[0].close, string.length - 1)
    }

    /// Empty containers count nothing and stay on one line, and summaries say keys or items, singular for one.
    func testEmptyContainersAndSummaries() {
        let outline = JSONOutline(#"{"a": {}, "b": [], "c": [[]], "d": [{"x": 1}], "e": {"y": [1, 2]}}"#)
        XCTAssertEqual(outline.containers.map(\.count), [5, 0, 0, 1, 0, 1, 1, 1, 2])
        XCTAssertEqual(outline.containers.map(\.summary), ["{ 5 keys }", "{ 0 keys }", "[ 0 items ]", "[ 1 item ]",
                                                           "[ 0 items ]", "[ 1 item ]", "{ 1 key }", "{ 1 key }",
                                                           "[ 2 items ]"])
        XCTAssertFalse(outline.containers.contains(where: \.isFoldable))
        XCTAssertEqual(outline.values.filter { $0.kind == .number }.map(\.keyPath), ["d.x", "e.y", "e.y"])
    }

    /// An array of objects: each object takes the array's key path, and its keys follow it.
    func testArraysOfObjects() {
        let outline = JSONOutline(#"[{"x": 1, "y": [{"z": "s"}]}, {"x": 2}]"#)
        XCTAssertEqual(outline.values.map(\.keyPath), ["", "", "x", "y", "y", "y.z", "", "x"])
        XCTAssertEqual(outline.values.map(\.isInArray), [false, true, true, true, true, true, true, true])
        XCTAssertEqual(outline.containers.map(\.count), [2, 2, 1, 1, 1])
    }

    /// JSON Lines: each line's record is a value at the top.
    func testValuesAtTheTop() {
        let text = "{\"a\": 1}\n{\"a\": [2]}\n3 \"s\" true null"
        let outline = JSONOutline(text)
        let top = outline.values.filter { $0.parent == nil }
        XCTAssertEqual(top.map(\.kind), [.object, .object, .number, .string, .boolean, .null])
        XCTAssertEqual(outline.values.filter { $0.parent != nil }.map(\.keyPath), ["a", "a", "a"])
        XCTAssertEqual(outline.containers.map(\.startLine), [0, 1, 1])
    }

    /// The value at an offset is the innermost whose key or text holds it, and a bracket's match is its container's
    /// other bracket.
    func testValueAtOffsetAndMatchingBrackets() {
        let text = #"{"a" : [ 1 , {"b":"c"} ], "d":2}"#
        let string = text as NSString
        let outline = JSONOutline(text)
        /// - Parameter character: Text in the record.
        /// - Returns: The key path of the value at its first unit.
        func path(at character: String, from start: Int = 0) -> String? {
            let found = string.range(of: character, range: NSRange(location: start, length: string.length - start))
            return outline.value(at: found.location).map { outline.values[$0].keyPath }
        }
        XCTAssertEqual(path(at: #""a""#), "a")
        XCTAssertEqual(path(at: ":"), "a")
        XCTAssertEqual(path(at: "1"), "a")
        XCTAssertEqual(path(at: " ,"), "a")
        XCTAssertEqual(path(at: #""b""#), "a.b")
        XCTAssertEqual(path(at: #""c""#), "a.b")
        XCTAssertEqual(path(at: ", \"d"), "")
        XCTAssertEqual(path(at: "2"), "d")
        XCTAssertEqual(outline.value(at: 0), 0)
        XCTAssertNil(outline.value(at: string.length))
        XCTAssertNil(outline.value(at: -1))
        let close = string.length - 1
        XCTAssertEqual(outline.matchingBracket(at: 0), close)
        XCTAssertEqual(outline.matchingBracket(at: close), 0)
        let array = string.range(of: "[").location
        XCTAssertEqual(outline.matchingBracket(at: array), string.range(of: "]").location)
        XCTAssertEqual(outline.matchingBracket(at: string.range(of: "]").location), array)
        XCTAssertNil(outline.matchingBracket(at: string.range(of: "1").location))
        XCTAssertNil(outline.matchingBracket(at: string.range(of: "b").location))
    }

    /// Brackets inside strings never match, and an unclosed container matches nothing.
    func testBracketsInStringsAndUnclosed() {
        let text = #"{"a": "{[(", "b": ["#
        let string = text as NSString
        let outline = JSONOutline(text)
        XCTAssertNil(outline.matchingBracket(at: string.range(of: "{[(").location))
        XCTAssertNil(outline.matchingBracket(at: 0))
        XCTAssertEqual(outline.containers.map(\.close), [nil, nil])
        XCTAssertEqual(outline.containers.map(\.endLine), [0, 0])
        XCTAssertEqual(outline.values.map(\.range.length).first, string.length)
        XCTAssertNil(outline.foldable(onLine: 0))
    }

    /// Malformed JSON gives what was read: stray closers are skipped, misplaced values and brackets are skipped, and
    /// whatever is open runs to the end.
    func testMalformed() {
        let cases: [(String, [Int?])] = [
            ("[}", [nil]), ("{]", [nil]), ("}}]]", []), (#"{"a" [1]}"#, [8]), (#"{"a":1,,}"#, [8]),
            (#"{"a": "abc"#, [nil]), (#""\"#, []), ("[1 2 {]", [6]), (#"{"a":{"b":1}}}"#, [12, 11]),
            (#"[{"a":1]"#, [nil, nil]), ("", []), ("   ", []), ("nul", []), (#"{"a":-}"#, [6]),
        ]
        for (text, closes) in cases {
            let outline = JSONOutline(text)
            XCTAssertEqual(outline.containers.map(\.close), closes, text)
            assertSound(outline, text)
        }
        XCTAssertEqual(JSONOutline(#"{"a": "abc"#).values.last?.range, NSRange(location: 6, length: 4))
        XCTAssertEqual(JSONOutline("[1 2 {]").values.map(\.kind), [.array, .number])
    }

    /// Every prefix of a record, and seeded random JSON-like text, outlines without trapping, and every lookup on it
    /// stays in range.
    func testTruncatedAndRandomTextNeverTraps() throws {
        let record = #"{"a" : [1, {"b" : "x\"]"}, -2.5e3, true], "c\\" : {"d" : null}}"#
        let units = Array(record.utf16)
        for length in 0...units.count {
            let text = String(decoding: units.prefix(length), as: UTF16.self)
            assertSound(JSONOutline(text), text)
        }
        var generator = SeededGenerator(seed: 0x0071_1E00)
        let alphabet = Array(#"{}[]":,\ nul1-.eE"#.utf16) + [0x0A, 0x74, 0xD83D, 0xDE00]
        for _ in 0..<2_000 {
            let count = Int.random(in: 0...60, using: &generator)
            let units = (0..<count).map { _ in alphabet.randomElement(using: &generator)! }
            let text = String(decoding: units, as: UTF16.self)
            assertSound(JSONOutline(text), text)
        }
    }

    /// Every synthetic event's record, pretty-printed as the JSON tab shows it and on one line as JSONL writes it:
    /// every container closes and counts what `JSONSerialization` reads, every value's text is JSON, and every key
    /// path is one the telemetry schema has.
    func testRecordsAgreeWithJSONSerialization() throws {
        let model = try XCTUnwrap(ExportEncoder.model)
        let pretty = ExportEncoder(model: model, pretty: true), lines = ExportEncoder(model: model)
        var values = 0
        for record in try SyntheticCorpus.records() {
            for encoder in [pretty, lines] {
                let text = String(decoding: encoder.line(for: record.message), as: UTF8.self)
                let string = text as NSString
                let outline = JSONOutline(text)
                for container in outline.containers {
                    let close = try XCTUnwrap(container.close, record.label)
                    let range = NSRange(location: container.open, length: close + 1 - container.open)
                    let parsed = try JSONSerialization.jsonObject(with: Data(string.substring(with: range).utf8))
                    XCTAssertEqual((parsed as? NSDictionary)?.count ?? (parsed as? NSArray)?.count, container.count,
                                   record.label)
                }
                for value in outline.values {
                    let written = Data(string.substring(with: value.range).utf8)
                    XCTAssertNoThrow(try JSONSerialization.jsonObject(with: written, options: .fragmentsAllowed),
                                     record.label)
                    XCTAssertNotNil(RecordKeyPaths.shared.nodes[value.keyPath], "\(record.label): \(value.keyPath)")
                    if value.key != nil, let node = RecordKeyPaths.shared.nodes[value.keyPath] {
                        XCTAssertEqual(value.isInArray, node.isInArray, "\(record.label): \(value.keyPath)")
                    }
                }
                values += outline.values.count
                XCTAssertEqual(outline.values.filter { $0.parent == nil }.count, 1, record.label)
                pretty.reset()
                lines.reset()
            }
        }
        XCTAssertGreaterThan(values, 10_000)
    }

    /// The bundled telemetry schema, the largest JSON Mac Monitor shows: it outlines whole, and its top object folds
    /// from the first line to the last.
    func testTelemetrySchema() throws {
        let text = String(decoding: try TelemetrySchema.data(), as: UTF8.self)
        let outline = JSONOutline(text)
        XCTAssertGreaterThan(outline.containers.count, 1_000)
        XCTAssertTrue(outline.containers.allSatisfy { $0.close != nil })
        XCTAssertEqual(outline.foldable(onLine: 0), 0)
        XCTAssertGreaterThanOrEqual(outline.containers[0].endLine, outline.lines.count - 2)
        let parsed = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? NSDictionary)
        XCTAssertEqual(outline.containers[0].count, parsed.count)
        assertSound(outline, text)
    }

    /// Check an outline is sound: offsets in the text, values in order of their starts, containers' brackets and
    /// values agreeing, and lookups at every offset in range.
    ///
    /// - Parameters:
    ///   - outline: The outline.
    ///   - text: Its text.
    ///   - file: The file a failure is reported in.
    ///   - line: The line a failure is reported on.
    private func assertSound(_ outline: JSONOutline, _ text: String, file: StaticString = #filePath,
                             line: UInt = #line) {
        let length = text.utf16.count
        XCTAssertEqual(outline.lines.length, length, text, file: file, line: line)
        XCTAssertEqual(outline.values.map(\.start), outline.values.map(\.start).sorted(), text, file: file, line: line)
        for value in outline.values {
            XCTAssertTrue(value.range.location >= 0 && NSMaxRange(value.range) <= length, text, file: file, line: line)
            XCTAssertLessThanOrEqual(value.start, value.range.location, text, file: file, line: line)
        }
        for container in outline.containers {
            XCTAssertEqual(outline.values[container.value].range.location, container.open, text, file: file,
                           line: line)
            XCTAssertLessThan(container.close ?? container.open, length, text, file: file, line: line)
            XCTAssertLessThanOrEqual(container.startLine, container.endLine, text, file: file, line: line)
        }
        for offset in -1...length {
            if let index = outline.value(at: offset) {
                XCTAssertTrue(NSLocationInRange(offset, NSRange(location: outline.values[index].start,
                                                                length: NSMaxRange(outline.values[index].range)
                                                                    - outline.values[index].start)),
                              text, file: file, line: line)
            }
            if let match = outline.matchingBracket(at: offset) {
                XCTAssertEqual(outline.matchingBracket(at: match), offset, text, file: file, line: line)
            }
        }
    }
}
