//
//  TextLinesTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Lines
/// Pins ``TextLines``: where lines start, the line an offset is on against counting line feeds, and each line's range.
final class TextLinesTests: XCTestCase {
    /// Lines start at 0 and after each line feed, so a final line feed starts an empty line. Offsets are UTF-16 units.
    func testStarts() {
        XCTAssertEqual(TextLines("").starts, [0])
        XCTAssertEqual(TextLines("one").starts, [0])
        XCTAssertEqual(TextLines("one\n").starts, [0, 4])
        XCTAssertEqual(TextLines("a\r\nb\n\nc").starts, [0, 3, 5, 6])
        XCTAssertEqual(TextLines("😀\né").starts, [0, 3])
        XCTAssertEqual(TextLines("😀\né").length, 4)
    }

    /// Each offset's line is the number of line feeds before it, and offsets out of range are on the first or last.
    func testLineAtEveryOffset() {
        let text = "first\n\n  third line\n😀 fourth\n"
        let lines = TextLines(text)
        let units = Array(text.utf16)
        for offset in 0...units.count {
            XCTAssertEqual(lines.line(at: offset), units.prefix(offset).filter { $0 == 0x0A }.count, "\(offset)")
        }
        XCTAssertEqual(lines.line(at: -5), 0)
        XCTAssertEqual(lines.line(at: 1_000), lines.count - 1)
        XCTAssertEqual(lines.count, 5)
    }

    /// A line's range leaves out its line feed, and a line out of range is the first or the last.
    func testRanges() {
        let text = "ab\n\ncde\n" as NSString
        let lines = TextLines(text as String)
        XCTAssertEqual((0..<lines.count).map { text.substring(with: lines.range(of: $0)) }, ["ab", "", "cde", ""])
        XCTAssertEqual(lines.range(of: -1), NSRange(location: 0, length: 2))
        XCTAssertEqual(lines.range(of: 9), NSRange(location: 8, length: 0))
        XCTAssertEqual(TextLines("").range(of: 0), NSRange(location: 0, length: 0))
    }
}

