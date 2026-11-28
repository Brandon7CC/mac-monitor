//
//  ValuePredicate.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - A value's predicate
/// The predicate that matches a record by one of its values, as Event Facts' JSON copies it: `key.path == value` for a
/// string, number, Boolean or `null`, `ANY key.path == value` for one in an array, and `key.path != nil` for an object
/// or an array. Literals are written as Mac Monitor's indicators write them: strings in double quotes, Booleans as
/// `YES` and `NO`, `null` as `nil`, and numbers as the record writes them.
public enum ValuePredicate {
    /// `NSPredicate`'s own words, which a key path's key has to escape with `#`, as in `event.mprotect.#size`.
    static let reservedWords: Set<String> = [
        "AND", "OR", "IN", "NOT", "ALL", "ANY", "SOME", "NONE", "LIKE", "CASEINSENSITIVE", "CI", "MATCHES",
        "CONTAINS", "BEGINSWITH", "ENDSWITH", "BETWEEN", "NULL", "NIL", "SELF", "TRUE", "YES", "FALSE", "NO",
        "FIRST", "LAST", "SIZE", "ANYKEY", "SUBQUERY", "FETCH", "CAST", "TRUEPREDICATE", "FALSEPREDICATE"
    ]

    /// The predicate for a value of a record's JSON.
    ///
    /// - Parameters:
    ///   - index: The value, in the outline's ``JSONOutline/values``.
    ///   - outline: The record's outline.
    ///   - text: The record's JSON, which the outline was made from.
    /// - Returns: The predicate, or `nil` for the record itself, which has no key path.
    public static func predicate(for index: Int, in outline: JSONOutline, text: NSString) -> String? {
        let value = outline.values[index]
        guard !value.keyPath.isEmpty else { return nil }
        let path = keyPath(value.keyPath)
        let literal: String
        switch value.kind {
        case .object, .array:
            return "\(path) != nil"
        case .string:
            literal = IndicatorValue.literal(outline.copiedText(of: index, in: text)[...])
        case .number:
            literal = text.substring(with: value.range)
        case .boolean:
            literal = text.substring(with: value.range) == "true" ? "YES" : "NO"
        case .null:
            literal = "nil"
        }
        return (value.isInArray ? "ANY " : "") + "\(path) == \(literal)"
    }

    /// The predicate that matches a record by its event's type: `es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC"`, or,
    /// for a network flow, whose record has no `es_event_type`, its event's key: `event.new_flow != nil`.
    ///
    /// - Parameter name: The type's name, as a stored event's `es_event_type` holds it.
    /// - Returns: The predicate.
    public static func eventType(_ name: String) -> String {
        MacMonitorEvent(name: name) == nil ? "es_event_type == " + IndicatorValue.literal(name[...])
            : "event.\(name) != nil"
    }

    /// A key path as a predicate names it.
    ///
    /// - Parameter path: The key path, keys joined by dots.
    /// - Returns: It with `#` before each key that's one of `NSPredicate`'s own words.
    public static func keyPath(_ path: String) -> String {
        path.split(separator: ".", omittingEmptySubsequences: false)
            .map { reservedWords.contains($0.uppercased()) ? "#\($0)" : String($0) }
            .joined(separator: ".")
    }
}
