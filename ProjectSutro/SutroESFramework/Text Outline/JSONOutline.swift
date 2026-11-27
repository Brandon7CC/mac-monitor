//
//  JSONOutline.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - JSON outline
/// The objects, arrays and values of a JSON text, found in one pass (JSONOutline+Scanning.swift): what a read-only
/// JSON view folds, matches brackets with and reads key paths from. Offsets are UTF-16 units, as `NSString` and
/// `NSTextView` count them.
///
/// The pass respects strings and their escapes, so a bracket in a string is text. It never fails. Malformed or cut-off
/// JSON gives what was read before it broke. A container that's never closed has no ``Container/close``, and a bracket
/// that closes nothing open is skipped.
public struct JSONOutline {
    /// What a value is.
    public enum Kind: Equatable {
        case object, array, string, number, boolean, null
    }

    /// An object or an array.
    public struct Container: Equatable {
        /// Is it an array, not an object?
        public let isArray: Bool
        /// Where its `{` or `[` is.
        public let open: Int
        /// Where its `}` or `]` is, or `nil` when it's never closed.
        public internal(set) var close: Int?
        /// The line its open bracket is on, from 0.
        public let startLine: Int
        /// The line its close bracket is on, from 0. The last line when it's never closed.
        public internal(set) var endLine: Int
        /// How many keys or items it has.
        public internal(set) var count = 0
        /// The value it is, in ``JSONOutline/values``.
        public let value: Int

        /// Is it closed on a later line than it opens, so it can fold?
        public var isFoldable: Bool { close != nil && endLine > startLine }

        /// What a fold shows instead of it, such as `{ 7 keys }` or `[ 1 item ]`.
        public var summary: String {
            let noun = isArray ? (count == 1 ? "item" : "items") : (count == 1 ? "key" : "keys")
            return isArray ? "[ \(count) \(noun) ]" : "{ \(count) \(noun) }"
        }
    }

    /// One value: an object's member, an array's item, or a value at the top.
    public struct Value: Equatable {
        public let kind: Kind
        /// Its key, quotes included, when it's an object's member.
        public let key: NSRange?
        /// Its text. A string's quotes are included, and an object or array runs through its close bracket.
        public internal(set) var range: NSRange
        /// Its keys from the top value, joined by dots, without array indexes: `event.exec.args` for each argument.
        public let keyPath: String
        /// Is it in an array, as an item or inside one?
        public let isInArray: Bool
        /// The container it's in, in ``JSONOutline/containers``, or `nil` at the top.
        public let parent: Int?
        /// The container it is, for an object or an array.
        public let container: Int?

        /// Where it starts: at its key, else at its text.
        public var start: Int { key?.location ?? range.location }
    }

    /// Every object and array, in the order they open.
    public internal(set) var containers: [Container] = []
    /// Every value, in the order they start.
    public internal(set) var values: [Value] = []
    /// The text's lines.
    public internal(set) var lines = TextLines(starts: [0], length: 0)
    /// The first container that can fold on each line, by line.
    var foldable: [Int: Int] = [:]
}


// MARK: - Finding
public extension JSONOutline {
    /// The value at an offset.
    ///
    /// - Parameter offset: An offset in the text.
    /// - Returns: The innermost value whose key or text holds it, in ``values``, or `nil` outside every value.
    func value(at offset: Int) -> Int? {
        /// The last value that starts at or before the offset.
        var low = 0, high = values.count
        while low < high {
            let middle = (low + high) / 2
            if values[middle].start <= offset { low = middle + 1 } else { high = middle }
        }
        /// Values nest, so the one holding the offset is that one or a container around it.
        var index = low - 1
        while index >= 0 {
            let value = values[index]
            if offset < NSMaxRange(value.range) { return index }
            guard let parent = value.parent else { return nil }
            index = containers[parent].value
        }
        return nil
    }

    /// The bracket matching one.
    ///
    /// - Parameter offset: Where a bracket is.
    /// - Returns: Where the bracket that opens or closes the same container is, or `nil` when there's no bracket of
    ///   a container there, or it's never closed.
    func matchingBracket(at offset: Int) -> Int? {
        guard let value = value(at: offset), let index = values[value].container else { return nil }
        let container = containers[index]
        if container.open == offset { return container.close }
        return container.close == offset ? container.open : nil
    }

    /// The container that folds from a line.
    ///
    /// - Parameter line: A line, from 0.
    /// - Returns: The first container that opens on it and closes on a later line, in ``containers``.
    func foldable(onLine line: Int) -> Int? {
        foldable[line]
    }

    /// A value's text as Copy Value copies it.
    ///
    /// - Parameters:
    ///   - index: The value, in ``values``.
    ///   - text: The text the outline was made from.
    /// - Returns: A string unescaped, without its quotes, and anything else as written.
    func copiedText(of index: Int, in text: NSString) -> String {
        let value = values[index]
        let written = text.substring(with: value.range)
        guard value.kind == .string else { return written }
        return Self.unescaped(written) ?? written
    }

    /// A JSON string literal's value.
    ///
    /// - Parameter literal: The literal, quotes included.
    /// - Returns: The string it stands for, or `nil` when it isn't a whole literal.
    static func unescaped(_ literal: String) -> String? {
        try? JSONSerialization.jsonObject(with: Data(literal.utf8), options: .fragmentsAllowed) as? String
    }
}
