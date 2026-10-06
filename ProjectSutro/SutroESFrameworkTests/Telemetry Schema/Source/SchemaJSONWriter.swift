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
    static func text(_ value: OrderedJSON) -> String {
        var output = ""
        write(value, indent: 0, into: &output)
        return output + "\n"
    }
    
    /// Write a value at an indentation.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - indent: The indentation of the line it starts on, in spaces.
    ///   - output: Receives the text.
    private static func write(_ value: OrderedJSON, indent: Int, into output: inout String) {
        let inner = String(repeating: " ", count: indent + 2), closing = String(repeating: " ", count: indent)
        switch value {
        case .string(let text): output += quoted(text)
        case .integer(let number): output += String(number)
        case .boolean(let flag): output += flag ? "true" : "false"
        case .null: output += "null"
        case .array(let elements) where elements.isEmpty: output += "[]"
        case .object(let members) where members.isEmpty: output += "{}"
        case .array(let elements):
            if let line = inline(elements), indent + line.count <= inlineWidth {
                output += line
                return
            }
            output += "[\n"
            for (index, element) in elements.enumerated() {
                output += inner
                write(element, indent: indent + 2, into: &output)
                output += index == elements.count - 1 ? "\n" : ",\n"
            }
            output += closing + "]"
        case .object(let members):
            output += "{\n"
            for (index, member) in members.enumerated() {
                output += inner + quoted(member.key) + ": "
                write(member.value, indent: indent + 2, into: &output)
                output += index == members.count - 1 ? "\n" : ",\n"
            }
            output += closing + "}"
        }
    }
    
    /// An array of scalars on one line.
    ///
    /// - Parameter elements: The array's elements.
    /// - Returns: `["a", "b"]`, or `nil` if an element isn't a scalar.
    private static func inline(_ elements: [OrderedJSON]) -> String? {
        guard elements.allSatisfy(\.isScalar) else { return nil }
        var parts: [String] = []
        for element in elements {
            var part = ""
            write(element, indent: 0, into: &part)
            parts.append(part)
        }
        return "[" + parts.joined(separator: ", ") + "]"
    }
    
    /// A string as a JSON string literal: quotes, backslashes and control characters escaped, slashes and everything
    /// else as is.
    ///
    /// - Parameter text: The string.
    /// - Returns: The literal.
    static func quoted(_ text: String) -> String {
        var literal = "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": literal += "\\\""
            case "\\": literal += "\\\\"
            case "\n": literal += "\\n"
            case "\r": literal += "\\r"
            case "\t": literal += "\\t"
            case "\u{08}": literal += "\\b"
            case "\u{0C}": literal += "\\f"
            case _ where scalar.value < 0x20: literal += String(format: "\\u%04x", scalar.value)
            default: literal.unicodeScalars.append(scalar)
            }
        }
        return literal + "\""
    }
}
