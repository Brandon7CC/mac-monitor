//
//  JSONCanonicalForm.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import Foundation


// MARK: - Canonical JSON
/// JSON rewritten with every object's members in order of their raw key bytes, and nothing else changed: every
/// scalar keeps its exact text (escapes, digits, `null`), a duplicated key stays duplicated, and empty objects and
/// arrays stay.
///
/// `JSONEncoder` writes an object's members in its hash table's order, which changes from one encode to the next, so
/// two encodings of the same value can only be compared byte for byte in this form.
enum JSONCanonicalForm {
    /// Why some bytes aren't JSON.
    struct SyntaxError: Error {
        /// Where the bytes stop being JSON.
        let offset: Int
    }
    
    /// The canonical form of one JSON text.
    ///
    /// - Parameter json: The JSON.
    /// - Returns: The JSON with every object's members sorted, as text.
    /// - Throws: ``SyntaxError`` if the bytes aren't one JSON value.
    static func canonical(_ json: Data) throws -> String {
        var parser = Parser(bytes: Array(json))
        let value = try parser.value()
        parser.skipSpace()
        guard parser.index == parser.bytes.count else { throw SyntaxError(offset: parser.index) }
        return String(decoding: value, as: UTF8.self)
    }
    
    /// Reads JSON, writing each value's canonical bytes.
    private struct Parser {
        let bytes: [UInt8]
        var index = 0
        
        /// Step over whitespace.
        mutating func skipSpace() {
            while index < bytes.count, [0x20, 0x09, 0x0a, 0x0d].contains(bytes[index]) { index += 1 }
        }
        
        /// The byte at the current position, or a syntax error at the end.
        ///
        /// - Returns: The byte.
        /// - Throws: ``SyntaxError`` at the end of the bytes.
        func current() throws -> UInt8 {
            guard index < bytes.count else { throw SyntaxError(offset: index) }
            return bytes[index]
        }
        
        /// Read the value at the current position.
        ///
        /// - Returns: Its canonical bytes.
        /// - Throws: ``SyntaxError`` if it isn't a value.
        mutating func value() throws -> [UInt8] {
            skipSpace()
            switch try current() {
            case UInt8(ascii: "{"): return try object()
            case UInt8(ascii: "["): return try array()
            default: return try scalar()
            }
        }
        
        /// Read an object, sorting its members by their raw key bytes.
        ///
        /// - Returns: Its canonical bytes.
        /// - Throws: ``SyntaxError`` if it isn't an object.
        mutating func object() throws -> [UInt8] {
            index += 1
            var members: [(key: [UInt8], value: [UInt8])] = []
            skipSpace()
            if try current() == UInt8(ascii: "}") {
                index += 1
                return Array("{}".utf8)
            }
            while true {
                skipSpace()
                let key = try scalar()
                skipSpace()
                guard try current() == UInt8(ascii: ":") else { throw SyntaxError(offset: index) }
                index += 1
                members.append((key, try value()))
                skipSpace()
                let separator = try current()
                index += 1
                if separator == UInt8(ascii: "}") { break }
                guard separator == UInt8(ascii: ",") else { throw SyntaxError(offset: index - 1) }
            }
            let sorted = members.enumerated().sorted { lhs, rhs in
                lhs.element.key == rhs.element.key ? lhs.offset < rhs.offset
                    : lhs.element.key.lexicographicallyPrecedes(rhs.element.key)
            }
            let body = sorted.map { $0.element.key + [UInt8(ascii: ":")] + $0.element.value }
            return [UInt8(ascii: "{")] + Array(body.joined(separator: [UInt8(ascii: ",")])) + [UInt8(ascii: "}")]
        }
        
        /// Read an array.
        ///
        /// - Returns: Its canonical bytes.
        /// - Throws: ``SyntaxError`` if it isn't an array.
        mutating func array() throws -> [UInt8] {
            index += 1
            var items: [[UInt8]] = []
            skipSpace()
            if try current() == UInt8(ascii: "]") {
                index += 1
                return Array("[]".utf8)
            }
            while true {
                items.append(try value())
                skipSpace()
                let separator = try current()
                index += 1
                if separator == UInt8(ascii: "]") { break }
                guard separator == UInt8(ascii: ",") else { throw SyntaxError(offset: index - 1) }
            }
            return [UInt8(ascii: "[")] + Array(items.joined(separator: [UInt8(ascii: ",")])) + [UInt8(ascii: "]")]
        }
        
        /// Read a string, number or literal, exactly as written.
        ///
        /// - Returns: Its bytes.
        /// - Throws: ``SyntaxError`` if there's none.
        mutating func scalar() throws -> [UInt8] {
            let start = index
            if try current() == UInt8(ascii: "\"") {
                index += 1
                while try current() != UInt8(ascii: "\"") {
                    index += bytes[index] == UInt8(ascii: "\\") ? 2 : 1
                }
                index += 1
            } else {
                let ends: [UInt8] = Array(",}] \t\r\n".utf8)
                while index < bytes.count, !ends.contains(bytes[index]) { index += 1 }
            }
            guard index > start else { throw SyntaxError(offset: index) }
            return Array(bytes[start..<index])
        }
    }
}
