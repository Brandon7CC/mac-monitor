//
//  ESStringTokenTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - String tokens
/// Pins how an `es_string_token_t` is read: as eslogger reads it, `NULL` is `nil`, an empty token is "", and `length`
/// (not a NUL) ends the text.
final class ESStringTokenTests: XCTestCase {
    /// A token whose `data` is `NULL` has no text, whatever its `length` says.
    func testNULLIsNil() {
        XCTAssertNil(es_string_token_t(length: 5, data: nil).string)
        XCTAssertNil(es_string_token_t(length: 0, data: nil).string)
    }
    
    /// An empty token is "", not `nil`.
    func testEmptyIsEmpty() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        XCTAssertEqual(fixture.token("").string, "")
    }
    
    /// `length` bounds the read: the bytes after it aren't read, NUL or not.
    func testLengthBoundsTheRead() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        XCTAssertEqual(fixture.token(bytes: Array("abcdef".utf8), length: 3).string, "abc")
        XCTAssertEqual(fixture.token(bytes: Array("abc".utf8)).string, "abc")
    }
    
    /// Bytes that aren't UTF-8 become U+FFFD, as eslogger writes them.
    func testInvalidUTF8IsRepaired() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        XCTAssertEqual(fixture.token(bytes: [0x61, 0xFF, 0x62]).string, "a\u{FFFD}b")
    }
    
    /// For showing a value, `nil` and "" both mean there's none.
    func testNonEmpty() {
        XCTAssertNil(String?.none.nonEmpty)
        XCTAssertNil(String?.some("").nonEmpty)
        XCTAssertEqual(String?.some("com.example.tool").nonEmpty, "com.example.tool")
    }
}
