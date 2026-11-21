//
//  IndicatorMatchedField.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/17/26.
//

import Foundation


// MARK: - What a hit matched
/// One comparison of an indicator's rule that an event passed: the key path it read, and the value the event had
/// there. A hit lists them (``IndicatorHit/matched``), so whoever reads it sees why the rule fired without
/// evaluating the rule again.
///
/// Only comparisons that say what the event has are listed: `==`, an ordering, `IN`, `BEGINSWITH`, `ENDSWITH`,
/// `CONTAINS`, `LIKE`, `!= nil`, the one value `ANY` found, and both sides of two fields compared. What a rule only
/// rules out, with `!=` a value or under `NOT`, isn't.
public struct IndicatorMatchedField: Codable, Hashable, Sendable {
    /// A value an event had, as its record writes it. A record's numbers are whole.
    public enum Value: Hashable, Sendable {
        case string(String)
        case integer(Int64)
        case boolean(Bool)
    }

    /// The most a hit lists.
    static let limit = 16
    /// The most of a string value that's kept, in characters. A command line can be megabytes.
    static let valueLimit = 256

    /// The key path the comparison read, as the rule names it.
    public let field: String
    /// What the event had there: a string's first ``valueLimit`` characters.
    public let value: Value

    /// - Parameters:
    ///   - field: The key path.
    ///   - value: The event's value.
    public init(field: String, value: Value) {
        self.field = field
        self.value = value
    }

    /// Strictly, whatever the decoder: Open Trace's fills in what's missing, so an entry without its field or value
    /// would otherwise be kept with made-up ones.
    ///
    /// - Parameter decoder: A decoder holding one entry of a hit's `matched`.
    /// - Throws: When a key is missing or `null`, or the value isn't a string, a whole number or a Boolean.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        field = try container.decodePresent(String.self, forKey: .field)
        value = try container.decodePresent(Value.self, forKey: .value)
    }

    /// An entry's keys in a record.
    private enum CodingKeys: String, CodingKey {
        case field, value
    }
}


extension IndicatorMatchedField.Value: Codable {
    /// The value an indicator's field read, as a record writes it, or `nil` for none or an array.
    ///
    /// - Parameters:
    ///   - value: What the field read.
    ///   - kind: What the field is: a Boolean reads as the number 1 or 0.
    init?(_ value: IndicatorValue, kind: IndicatorField.Kind) {
        switch value {
        case .string(let string):
            self = .string(Self.cut(string))
        case .number(let number, _):
            if kind == .boolean {
                self = .boolean(number != 0)
            } else if let whole = Int64(exactly: number) {
                self = .integer(whole)
            } else {
                return nil
            }
        case .null, .strings:
            return nil
        }
    }

    /// - Parameter string: A string value.
    /// - Returns: Its first ``IndicatorMatchedField/valueLimit`` characters.
    static func cut(_ string: some StringProtocol) -> String {
        String(String.UnicodeScalarView(string.unicodeScalars.prefix(IndicatorMatchedField.valueLimit)))
    }

    /// The kind is the JSON value's own. Open Trace's decoder reads a number as a Boolean and a string of digits
    /// as a number when asked to, so its value is read as it is.
    ///
    /// - Parameter decoder: A decoder holding a JSON string, whole number or Boolean.
    /// - Throws: When it holds anything else.
    public init(from decoder: Decoder) throws {
        if let trace = decoder as? TraceDecoder {
            switch trace.value {
            case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID():
                self = .boolean(number.boolValue)
            case let number as NSNumber where Double(exactly: number).flatMap(Int64.init(exactly:)) != nil:
                self = .integer(number.int64Value)
            case let text as NSString:
                self = .string(text as String)
            default:
                throw DecodingError.typeMismatch(Self.self, .init(codingPath: decoder.codingPath,
                                                                  debugDescription: "Not a string, a whole "
                                                                    + "number or a Boolean."))
            }
            return
        }
        let container = try decoder.singleValueContainer()
        if let boolean = try? container.decode(Bool.self) {
            self = .boolean(boolean)
        } else if let integer = try? container.decode(Int64.self) {
            self = .integer(integer)
        } else {
            self = .string(try container.decode(String.self))
        }
    }

    /// - Parameter encoder: The encoder.
    /// - Throws: When the value can't be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let string): try container.encode(string)
        case .integer(let integer): try container.encode(integer)
        case .boolean(let boolean): try container.encode(boolean)
        }
    }
}
