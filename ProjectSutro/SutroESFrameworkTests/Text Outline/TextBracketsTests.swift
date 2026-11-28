//
//  TextBracketsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Brackets
/// Pins ``TextBrackets``: each kind of bracket matched both ways by its nesting, nothing for a bracket without a match
/// in reach, and nothing for text that isn't a bracket.
final class TextBracketsTests: XCTestCase {
    /// Round, square and curly brackets match by nesting, forward from an open bracket and back from a close.
    func testMatches() {
        let text = "f(a[0], { b: (c) }) ]" as NSString
        /// - Parameter character: A bracket in the text, by its first appearance.
        /// - Returns: Where its match is.
        func match(_ character: String) -> Int? {
            TextBrackets.match(at: text.range(of: character).location, in: text)
        }
        XCTAssertEqual(match("("), 18)
        XCTAssertEqual(match("["), text.range(of: "]").location)
        XCTAssertEqual(match("{"), text.range(of: "}").location)
        XCTAssertEqual(TextBrackets.match(at: text.range(of: "}").location, in: text), text.range(of: "{").location)
        XCTAssertEqual(TextBrackets.match(at: 18, in: text), 1)
        XCTAssertNil(TextBrackets.match(at: text.length - 1, in: text))
        XCTAssertNil(match("a"))
        XCTAssertNil(TextBrackets.match(at: -1, in: text))
        XCTAssertNil(TextBrackets.match(at: text.length, in: text))
    }

    /// A match farther than the limit isn't found.
    func testLimit() {
        let text = ("(" + String(repeating: "x", count: 10) + ")") as NSString
        XCTAssertEqual(TextBrackets.match(at: 0, in: text, limit: 11), 11)
        XCTAssertNil(TextBrackets.match(at: 0, in: text, limit: 10))
        XCTAssertNil(TextBrackets.match(at: 11, in: text, limit: 10))
        XCTAssertEqual(TextBrackets.match(at: 11, in: text, limit: 11), 0)
    }
}
