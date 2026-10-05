//
//  StreamingJSONEncoderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Streaming JSON encoder
/// Pins ``StreamingJSONEncoder`` to `JSONEncoder`'s default output: every scalar byte for byte, and every structure
/// byte for byte once each object's members are sorted (``JSONCanonicalForm``), including values it leaves to
/// `JSONEncoder`.
final class StreamingJSONEncoderTests: XCTestCase {
    /// Encode with both encoders and require the same bytes, in canonical form.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - line: The caller's line, for failures.
    /// - Throws: Either encoder's error.
    private func assertSameJSON<T: Encodable>(_ value: T, line: UInt = #line) throws {
        let expected = try JSONCanonicalForm.canonical(try JSONEncoder().encode(value))
        XCTAssertEqual(try JSONCanonicalForm.canonical(try StreamingJSONEncoder().encode(value)), expected, line: line)
    }
    
    /// Encode an array with both encoders and require the very same bytes (arrays keep their order).
    ///
    /// - Parameters:
    ///   - values: The values.
    ///   - line: The caller's line, for failures.
    /// - Throws: Either encoder's error.
    private func assertSameBytes<T: Encodable>(_ values: [T], line: UInt = #line) throws {
        let expected = String(decoding: try JSONEncoder().encode(values), as: UTF8.self)
        XCTAssertEqual(String(decoding: try StreamingJSONEncoder().encode(values), as: UTF8.self), expected, line: line)
    }
    
    // MARK: Scalars
    
    /// Strings: every control character, quotes, backslashes, slashes, DEL, line and paragraph separators, accents,
    /// emoji, and random strings drawn from all of them.
    ///
    /// - Throws: Either encoder's error.
    func testStringsMatchByteForByte() throws {
        let controls = (0..<0x20).map { String(UnicodeScalar(UInt8($0))) }
        let specials = ["", "\"", "\\", "/", "</script>", "\u{7F}", "\u{2028}", "\u{2029}", "é", "e\u{301}", "😀",
                        "\u{00A0}", "\u{FEFF}", "C:\\Users\\a/b", "tab\there", "line\nbreak", "\u{10FFFF}"]
        try assertSameBytes(controls + specials)
        let alphabet = Array((controls + specials).joined()) + Array("abc XYZ 019 {}[]:,")
        let random = (0..<2_000).map { _ in
            String((0..<Int.random(in: 0...12)).map { _ in alphabet.randomElement()! })
        }
        try assertSameBytes(random)
        try assertSameBytes([String?.none, "set", nil])
    }
    
    /// Integers of every width at their ends and in between, and booleans.
    ///
    /// - Throws: Either encoder's error.
    func testIntegersAndBooleansMatchByteForByte() throws {
        try assertSameBytes([Int.min, -1, 0, 1, Int.max] + (0..<200).map { _ in Int.random(in: .min ... .max) })
        try assertSameBytes([Int8.min, -1, 0, Int8.max])
        try assertSameBytes([Int16.min, 0, Int16.max])
        try assertSameBytes([Int32.min, 0, Int32.max])
        try assertSameBytes([Int64.min, 0, Int64.max])
        try assertSameBytes([UInt.min, 9, 10, UInt.max])
        try assertSameBytes([UInt8.min, UInt8.max])
        try assertSameBytes([UInt16.min, UInt16.max])
        try assertSameBytes([UInt32.min, UInt32.max])
        try assertSameBytes([UInt64.min, UInt64.max] + (0..<200).map { _ in UInt64.random(in: .min ... .max) })
        try assertSameBytes([true, false])
    }
    
    /// Doubles and floats: zeros, whole numbers (written without `.0`), fractions, exponents, extremes, and random bit
    /// patterns.
    ///
    /// - Throws: Either encoder's error.
    func testNumbersMatchByteForByte() throws {
        let doubles: [Double] = [0, -0.0, 1, -1, 1.5, -2.25, 0.1, 1e-7, 1e15, 1e16, 1e21, 1e300, .pi,
                                 .leastNonzeroMagnitude, .leastNormalMagnitude, .greatestFiniteMagnitude,
                                 123_456_789.123_456_789, 812_764_914.314_153_7, 9_007_199_254_740_992,
                                 -4_503_599_627_370_497]
        let randomDoubles = (0..<2_000).map { _ in Double(bitPattern: UInt64.random(in: .min ... .max)) }
        try assertSameBytes(doubles + randomDoubles.filter(\.isFinite))
        let randomFloats = (0..<2_000).map { _ in Float(bitPattern: UInt32.random(in: .min ... .max)) }
        try assertSameBytes([Float(0), -0.0, 1, 1.5, 1e-7, .greatestFiniteMagnitude] + randomFloats.filter(\.isFinite))
    }
    
    /// Dates (seconds since 2001), UUIDs (uppercase), data (base64), URLs (absolute strings), and decimals.
    ///
    /// - Throws: Either encoder's error.
    func testFoundationValuesMatchByteForByte() throws {
        try assertSameBytes([Date(timeIntervalSinceReferenceDate: 0), Date(timeIntervalSince1970: 0),
                             Date(timeIntervalSince1970: 1_791_072_114.394_127)]
                            + (0..<200).map { _ in Date(timeIntervalSince1970: .random(in: -1e10...1e10)) })
        try assertSameBytes((0..<50).map { _ in UUID() })
        try assertSameBytes([Data(), Data([0]), Data((0...255).map(UInt8.init))])
        try assertSameBytes([URL(fileURLWithPath: "/tmp/a b"), URL(string: "https://example.com/a?b=c&d=/e")!])
        try assertSameBytes([Decimal(0), Decimal(string: "3.14159")!, Decimal(-12)])
    }
    
    /// A number that isn't finite is refused, as `JSONEncoder` refuses it.
    func testNonFiniteNumbersThrow() {
        for value in [Double.nan, .infinity, -.infinity] {
            XCTAssertThrowsError(try StreamingJSONEncoder().encode(["value": value]))
            XCTAssertThrowsError(try JSONEncoder().encode(["value": value]))
        }
        XCTAssertThrowsError(try StreamingJSONEncoder().encode([Float.nan]))
    }
}
