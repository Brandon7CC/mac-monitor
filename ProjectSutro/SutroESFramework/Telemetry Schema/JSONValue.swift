//
//  JSONValue.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - JSON types
/// A JSON value's type, by its JSON Schema name.
enum JSONType: String, CaseIterable, Sendable {
    case null, boolean, integer, number, string, array, object
    
    /// The type of a `JSONSerialization` value.
    ///
    /// A Boolean is never a number (`NSNumber(1)` and `true` are different JSON values), and a number is an integer
    /// when it has no fraction: `1.0` is one, and so are a `UInt64` above `Int64.max` and an `NSDecimalNumber`, which
    /// `JSONSerialization` makes of longer integers.
    ///
    /// The value is bridged to an object once and classified by its class, most common first: a Swift dynamic cast
    /// from `Any` for each type took most of a check's time.
    ///
    /// - Parameter value: `NSNull`, an `NSNumber`, a string, an array, or a dictionary.
    init?(of value: Any) {
        let object = value as AnyObject
        if object is NSString {
            self = .string
        } else if object is NSDictionary {
            self = .object
        } else if object is NSArray {
            self = .array
        } else if let number = object as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { self = .boolean }
            else { self = Self.isIntegral(number) ? .integer : .number }
        } else if object is NSNull {
            self = .null
        } else {
            return nil
        }
    }
    
    /// Does a value of this type satisfy a schema that allows `allowed`? An integer is also a number.
    ///
    /// - Parameter allowed: The schema's types.
    /// - Returns: `true` if it does.
    func satisfies(_ allowed: [JSONType]) -> Bool {
        allowed.contains(self) || (self == .integer && allowed.contains(.number))
    }
    
    /// Is a number that isn't a Boolean an integer?
    ///
    /// - Parameter number: The number.
    /// - Returns: `true` if it has no fraction.
    static func isIntegral(_ number: NSNumber) -> Bool {
        if let decimal = number as? NSDecimalNumber {
            var value = decimal.decimalValue, whole = Decimal()
            NSDecimalRound(&whole, &value, 0, .plain)
            return !value.isNaN && whole == value
        }
        switch UInt8(bitPattern: number.objCType.pointee) {
        case UInt8(ascii: "f"), UInt8(ascii: "d"):
            let value = number.doubleValue
            return value.isFinite && value.rounded(.towardZero) == value
        default:
            return true
        }
    }
}


// MARK: - JSON scalars
/// A JSON scalar compared by value and type, for `enum` and `const`: `NSNumber(1).isEqual(true)` is `true`, but `1`
/// and `true` are different JSON values.
enum JSONScalar: Hashable, Sendable, CustomStringConvertible {
    case null, boolean(Bool), integer(Int), string(String)
    
    /// A `JSONSerialization` value as a scalar.
    ///
    /// - Parameter value: The value.
    /// - Returns: `nil` for an array, an object, a number with a fraction, or an integer too large for `Int`, which
    ///   equal no scalar a schema can name.
    init?(_ value: Any) {
        self.init(value, of: JSONType(of: value))
    }
    
    /// A `JSONSerialization` value of a known type as a scalar, without classifying it again.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - type: Its type, as ``JSONType/init(of:)`` gives it.
    /// - Returns: `nil` for an array, an object, a number with a fraction, or an integer too large for `Int`.
    init?(_ value: Any, of type: JSONType?) {
        let object = value as AnyObject
        switch type {
        case .null: self = .null
        case .boolean: self = .boolean((object as! NSNumber).boolValue)
        case .integer:
            guard let integer = Self.integer(object as! NSNumber) else { return nil }
            self = .integer(integer)
        case .string: self = .string(object as! String)
        default: return nil
        }
    }
    
    /// An integral number's value, if it fits in an `Int`.
    ///
    /// - Parameter number: A number that ``JSONType/init(of:)`` calls an integer.
    /// - Returns: Its value.
    private static func integer(_ number: NSNumber) -> Int? {
        if number is NSDecimalNumber { return Int(number.stringValue) }
        switch UInt8(bitPattern: number.objCType.pointee) {
        case UInt8(ascii: "f"), UInt8(ascii: "d"): return Int(exactly: number.doubleValue)
        case UInt8(ascii: "Q"), UInt8(ascii: "L"), UInt8(ascii: "I"): return Int(exactly: number.uint64Value)
        default: return Int(exactly: number.int64Value)
        }
    }
    
    /// The scalar as JSON text: `null`, `true`, `12`, or a quoted string.
    var description: String {
        switch self {
        case .null: "null"
        case .boolean(let value): "\(value)"
        case .integer(let value): "\(value)"
        case .string(let value): JSONText.quoted(value)
        }
    }
}


// MARK: - JSON text for messages
/// Short renderings of JSON values for issue messages.
enum JSONText {
    /// The longest string an issue quotes in full.
    static let maxQuoted = 80
    
    /// A string as a JSON string literal, cut to ``maxQuoted`` characters.
    ///
    /// - Parameter text: The string.
    /// - Returns: The literal, with quotes, backslashes and control characters escaped and slashes left alone.
    static func quoted(_ text: String) -> String {
        let shown = cut(text)
        let options: JSONSerialization.WritingOptions = [.fragmentsAllowed, .withoutEscapingSlashes]
        let data = try? JSONSerialization.data(withJSONObject: shown, options: options)
        return data.map { String(decoding: $0, as: UTF8.self) } ?? "\"\(shown)\""
    }
    
    /// Text from a record, cut to ``maxQuoted`` characters before it's kept, so a key or value of megabytes takes no
    /// more of a report than a short one. Counts no further than the limit.
    ///
    /// - Parameter text: The text.
    /// - Returns: The text, or its first ``maxQuoted`` characters and `…`.
    static func cut(_ text: String) -> String {
        text.dropFirst(maxQuoted).isEmpty ? text : String(text.prefix(maxQuoted)) + "…"
    }
    
    /// A value as an issue shows it: a scalar as JSON, a container by its type.
    ///
    /// - Parameter value: A `JSONSerialization` value.
    /// - Returns: `"text"`, `12`, `1.5`, `true`, `null`, `an array`, or `an object`.
    static func describe(_ value: Any) -> String {
        switch JSONType(of: value) {
        case .array: "an array"
        case .object: "an object"
        case .number: (value as! NSNumber).stringValue
        case .integer: (value as! NSNumber).stringValue
        case nil: "\(type(of: value))"
        default: JSONScalar(value)?.description ?? "\(value)"
        }
    }
}
