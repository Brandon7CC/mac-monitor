//
//  SchemaJSONWriter.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Ordered JSON
/// A JSON value whose objects keep their keys in order, so the schema's `$schema` and `$id` come first and its `$defs`
/// last, which `JSONSerialization`'s sorted keys can't do.
indirect enum OrderedJSON: Equatable {
    /// A string, an integer, a Boolean, or `null`.
    case string(String), integer(Int), boolean(Bool), null
    /// An array: its elements, in order.
    case array([OrderedJSON])
    /// An object: its members, in the order they're written.
    case object([Member])
    
    /// One key of an object, and its value.
    struct Member: Equatable {
        /// The key.
        let key: String
        /// Its value.
        let value: OrderedJSON
    }
    
    /// The value as `JSONSerialization` would read it, for comparing with a parsed file.
    var foundation: Any {
        switch self {
        case .string(let text): text
        case .integer(let number): number
        case .boolean(let flag): flag
        case .null: NSNull()
        case .array(let elements): elements.map(\.foundation)
        case .object(let members): Dictionary(uniqueKeysWithValues: members.map { ($0.key, $0.value.foundation) })
        }
    }
    
    /// Is the value a string, a number, a Boolean or `null`?
    var isScalar: Bool {
        switch self {
        case .array, .object: false
        default: true
        }
    }
}


// MARK: - Writer
/// Writes the schema the same way every time: two-space indentation, keys in the order given, slashes unescaped, and
/// arrays of scalars on one line when they fit.
enum SchemaJSONWriter {
    /// The widest line an array of scalars is written on.
    static let inlineWidth = 100
    
    /// A document's text.
    ///
    /// - Parameter value: The document.
    /// - Returns: Its JSON text, ending in a newline.
    static func text(_ value: OrderedJSON) -> String { text(value, indent: 0) + "\n" }
    
    /// A value's text at an indentation.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - indent: The indentation of the line it starts on, in spaces.
    /// - Returns: Its JSON text, without a trailing newline.
    private static func text(_ value: OrderedJSON, indent: Int) -> String {
        let inner = String(repeating: " ", count: indent + 2), closing = String(repeating: " ", count: indent)
        switch value {
        case .string(let text): return quoted(text)
        case .integer(let number): return String(number)
        case .boolean(let flag): return flag ? "true" : "false"
        case .null: return "null"
        case .array(let elements) where elements.isEmpty: return "[]"
        case .object(let members) where members.isEmpty: return "{}"
        case .array(let elements):
            if elements.allSatisfy(\.isScalar) {
                let line = "[" + elements.map { text($0, indent: 0) }.joined(separator: ", ") + "]"
                if indent + line.count <= inlineWidth { return line }
            }
            return "[\n" + elements.map { inner + text($0, indent: indent + 2) }.joined(separator: ",\n")
                + "\n" + closing + "]"
        case .object(let members):
            return "{\n" + members.map { inner + quoted($0.key) + ": " + text($0.value, indent: indent + 2) }
                .joined(separator: ",\n") + "\n" + closing + "}"
        }
    }
    
    /// A string as a JSON string literal: quotes, backslashes and control characters escaped, slashes and everything
    /// else as is.
    ///
    /// - Parameter text: The string.
    /// - Returns: The literal.
    static func quoted(_ text: String) -> String {
        /// A string with fragments allowed is always JSON.
        let options: JSONSerialization.WritingOptions = [.fragmentsAllowed, .withoutEscapingSlashes]
        return String(decoding: try! JSONSerialization.data(withJSONObject: text, options: options), as: UTF8.self)
    }
}
