//
//  XCTestCase+JSON.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest


// MARK: - eslogger's key paths
extension XCTestCase {
    /// Keys that count one Endpoint Security client's messages, which never match another client's: left out when
    /// Mac Monitor's export is compared with eslogger's record.
    static let esloggerSequenceNumbers: Set<String> = ["seq_num", "global_seq_num"]
    
    /// The records of a JSON Lines fixture.
    ///
    /// - Parameter name: The fixture's file name, with its extension.
    /// - Returns: Each line's object.
    /// - Throws: An `XCTest` failure if the fixture is missing or a line isn't a JSON object.
    func fixtureRecords(_ name: String) throws -> [[String: Any]] {
        try String(decoding: try fixture(name), as: UTF8.self).split(separator: "\n").map { line in
            try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
        }
    }
    
    /// A JSON value as Mac Monitor's exports write it: keys sorted, slashes left alone, pretty-printed or on one line.
    ///
    /// - Parameters:
    ///   - value: The value: an object or an array.
    ///   - pretty: Pretty-printed, as the pretty export writes it.
    /// - Returns: The value's JSON text.
    /// - Throws: The error serializing it.
    func jsonText(_ value: Any, pretty: Bool = false) throws -> String {
        var options: JSONSerialization.WritingOptions = [.sortedKeys, .withoutEscapingSlashes]
        if pretty { options.insert(.prettyPrinted) }
        return String(decoding: try JSONSerialization.data(withJSONObject: value, options: options), as: UTF8.self)
    }
    
    /// The places where `actual` differs from `expected` on `expected`'s key paths: every value `expected` has must be
    /// at the same key path in `actual`, with the same JSON type and value. `actual` may have more keys.
    ///
    /// Booleans and numbers are different types (eslogger writes `true`, never `1`), and numbers compare exactly.
    ///
    /// - Parameters:
    ///   - expected: A `JSONSerialization` value, such as an eslogger record.
    ///   - actual: The value to check, such as Mac Monitor's export of the record's event.
    ///   - ignoring: Keys not compared, at any depth.
    ///   - path: The key path of `expected`.
    /// - Returns: One line per difference: its key path, and both values.
    func differences(_ expected: Any, _ actual: Any?, ignoring: Set<String> = [], path: String = "") -> [String] {
        switch expected {
        case let object as [String: Any]:
            guard let other = actual as? [String: Any] else {
                return ["\(path): expected an object, found \(String(describing: actual))"]
            }
            return object.keys.sorted().filter { !ignoring.contains($0) }.flatMap { key -> [String] in
                let child = path.isEmpty ? key : "\(path).\(key)"
                guard let value = other[key] else { return ["\(child): missing"] }
                return differences(object[key]!, value, ignoring: ignoring, path: child)
            }
        case let array as [Any]:
            guard let other = actual as? [Any], other.count == array.count else {
                return ["\(path): expected \(array.count) elements, found \(String(describing: actual))"]
            }
            return zip(array, other).enumerated().flatMap { index, pair in
                differences(pair.0, pair.1, ignoring: ignoring, path: "\(path)[\(index)]")
            }
        default:
            guard Self.sameScalar(expected, actual) else {
                return ["\(path): expected \(expected), found \(String(describing: actual))"]
            }
            return []
        }
    }
    
    /// Assert that `actual` has every value `expected` has, at the same key path
    /// (see ``differences(_:_:ignoring:path:)``).
    ///
    /// - Parameters:
    ///   - expected: A `JSONSerialization` value, such as an eslogger record.
    ///   - actual: The value to check.
    ///   - ignoring: Keys not compared, at any depth.
    ///   - message: Names the value, for the failure message.
    ///   - file: The caller's file.
    ///   - line: The caller's line.
    func assertContains(_ expected: Any, _ actual: Any?, ignoring: Set<String> = [], _ message: String = "",
                        file: StaticString = #filePath, line: UInt = #line) {
        let found = differences(expected, actual, ignoring: ignoring)
        XCTAssertTrue(found.isEmpty, "\(message): \(found.joined(separator: "; "))", file: file, line: line)
    }
    
    /// Are two `JSONSerialization` scalars the same JSON value of the same JSON type?
    ///
    /// - Parameters:
    ///   - expected: `NSNull`, a string, a Boolean or a number.
    ///   - actual: The value to compare with it.
    /// - Returns: `true` if they're equal and of the same type.
    private static func sameScalar(_ expected: Any, _ actual: Any?) -> Bool {
        switch (expected, actual) {
        case (is NSNull, is NSNull):
            return true
        case (let left as String, let right as String):
            return left == right
        case (let left as NSNumber, let right as NSNumber):
            return isBoolean(left) == isBoolean(right) && left.isEqual(to: right)
        default:
            return false
        }
    }
    
    /// Is a `JSONSerialization` number a JSON Boolean?
    ///
    /// - Parameter number: The number.
    /// - Returns: `true` for `true` and `false`.
    private static func isBoolean(_ number: NSNumber) -> Bool {
        CFGetTypeID(number) == CFBooleanGetTypeID()
    }
}
