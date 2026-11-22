//
//  PredicateLayout+Passed.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/22/26.
//

import Foundation


// MARK: - The lines an event passed
public extension PredicateLayout {
    /// The lines whose condition an event passed, which Event Facts' Indicators popover marks. Each line's condition
    /// is evaluated on what a hit says the event had (``IndicatorHit/matched``), and on the event's type.
    ///
    /// A line is passed when it reads a key path the hit lists, or the event's type, and its condition holds there.
    /// A hit lists only what an event has, so a line that only rules something out is never passed: one that starts
    /// with `NOT`, one in a group under `NOT`, and a `!=` a value. A value the hit cut short
    /// (``IndicatorMatchedField/Value/isCut``) can't always be checked, so a line that reads one is passed.
    ///
    /// - Parameters:
    ///   - matched: What the hit lists.
    ///   - eventType: The event's type, such as `ES_EVENT_TYPE_NOTIFY_EXEC`, or `nil` when it isn't known.
    /// - Returns: The passed lines' places in ``lines``.
    func passedLines(by matched: [IndicatorMatchedField], eventType: String? = nil) -> IndexSet {
        let facts = PassedFacts(matched, eventType: eventType)
        var passed = IndexSet()
        /// The depth of the line that opened the group under `NOT` being skipped.
        var negated: Int?
        for (index, line) in lines.enumerated() {
            if let depth = negated {
                if line.depth > depth { continue }
                negated = nil
            }
            let condition = LineCondition(line.text)
            if condition.opensNegatedGroup {
                negated = line.depth
            } else if facts.pass(condition) {
                passed.insert(index)
            }
        }
        return passed
    }
}


public extension IndicatorMatchedField.Value {
    /// May the hit have cut it short? A string as long as a hit keeps (``IndicatorMatchedField/valueLimit``).
    var isCut: Bool {
        if case .string(let string) = self { return string.unicodeScalars.count >= IndicatorMatchedField.valueLimit }
        return false
    }

    /// The value as a record writes it: a string as it is, a whole number, and `true` or `false`.
    var text: String {
        switch self {
        case .string(let string): return string
        case .integer(let number): return String(number)
        case .boolean(let boolean): return String(boolean)
        }
    }

    /// The value as `NSPredicate` compares it.
    fileprivate var object: Any {
        switch self {
        case .string(let string): return string as NSString
        case .integer(let number): return NSNumber(value: number)
        case .boolean(let boolean): return NSNumber(value: boolean)
        }
    }
}


// MARK: - A line's condition
/// The condition on one line of a ``PredicateLayout``: the line without the `AND` or `OR` that starts it and the `(`
/// that ends it when it opens a group.
private struct LineCondition {
    /// The condition, or `nil` for a line without one: a group's `(` or `)`.
    let text: String?
    /// Does the line open a group under `NOT`, as `AND NOT (` does?
    let opensNegatedGroup: Bool
    /// Does it only rule something out: `NOT`, `NONE`, or `!=` anything but `nil`?
    let rulesOut: Bool
    /// Does it compare any of an array's strings, with `ANY` or `SOME`?
    let isAny: Bool
    /// The key paths it reads.
    let keyPaths: [String]

    /// The words that join conditions, which start a line.
    private static let joiners: Set<String> = ["AND", "OR"]

    /// - Parameter line: A line's text, without its indentation.
    init(_ line: String) {
        var text = line.trimmingCharacters(in: .whitespaces)
        for symbol in ["&&", "||"] where text.hasPrefix(symbol) { text.removeFirst(symbol.count) }
        text = text.trimmingCharacters(in: .whitespaces)
        var tokens = PredicateText.tokens(in: text)
        if let first = tokens.first, first.range.location == 0, Self.joiners.contains(Self.word(first)) {
            text = (text as NSString).substring(from: NSMaxRange(first.range)).trimmingCharacters(in: .whitespaces)
            tokens = PredicateText.tokens(in: text)
        }
        let balance = Self.parentheses(in: text, outside: tokens)
        let opens = balance > 0 && text.hasSuffix("(")
        if opens { text = String(text.dropLast()).trimmingCharacters(in: .whitespaces) }
        let words = tokens.filter { [.keyword, .function].contains($0.kind) }.map(Self.word)
        opensNegatedGroup = opens && words.last == "NOT"
        rulesOut = words.first == "NOT" || text.hasPrefix("!") || words.contains("NONE")
            || tokens.indices.contains { index in
                tokens[index].text.hasPrefix("!=")
                    && !(tokens.indices.contains(index + 1) && ["NIL", "NULL"].contains(Self.word(tokens[index + 1])))
            }
        isAny = words.contains("ANY") || words.contains("SOME")
        keyPaths = tokens.filter { $0.kind == .keyPath }.map(\.text)
        self.text = opens || balance != 0 || text.isEmpty ? nil : text
    }

    /// - Parameter token: A token.
    /// - Returns: Its word in capitals, without a modifier such as `[c]`.
    private static func word(_ token: PredicateText.Token) -> String {
        token.text.uppercased().components(separatedBy: "[")[0]
    }

    /// - Parameters:
    ///   - text: A line's text.
    ///   - tokens: Its tokens.
    /// - Returns: How many more `(` than `)` it has outside its quoted strings.
    private static func parentheses(in text: String, outside tokens: [PredicateText.Token]) -> Int {
        let string = text as NSString
        let quoted = tokens.filter { $0.kind == .string }.map(\.range)
        var balance = 0
        for location in 0 ..< string.length where !quoted.contains(where: { NSLocationInRange(location, $0) }) {
            switch string.character(at: location) {
            case 0x28: balance += 1
            case 0x29: balance -= 1
            default: continue
            }
        }
        return balance
    }
}


// MARK: - What the event had
/// What a hit says an event had, as objects `NSPredicate` evaluates a line's condition on: the key paths the hit
/// lists with their values, the event's type under `es_event_type`, and its payload's key, such as `event.exec`.
private struct PassedFacts {
    /// Each listed key path's values, in the hit's order. Only an array's key path, which `ANY` read, has several.
    private var values: [String: [IndicatorMatchedField.Value]] = [:]
    /// The key paths that say the event's type: `es_event_type`, and its payload's.
    private var typePaths: Set<String> = []
    /// The event as a record, with one value at a key path that has one.
    private let record = NSMutableDictionary()
    /// The event as a record, with an array at every listed key path, as `ANY` reads one.
    private let arrays = NSMutableDictionary()

    /// - Parameters:
    ///   - matched: What the hit lists.
    ///   - eventType: The event's type, or `nil`.
    init(_ matched: [IndicatorMatchedField], eventType: String?) {
        for field in matched { values[field.field, default: []].append(field.value) }
        if let eventType {
            let payload = "event." + eventType.replacingOccurrences(of: "ES_EVENT_TYPE_NOTIFY_", with: "").lowercased()
            typePaths = ["es_event_type"]
            set(eventType as NSString, at: "es_event_type")
            if PredicateEventTypes.payloads[payload] == eventType {
                typePaths.insert(payload)
                set(NSMutableDictionary(), at: payload)
            }
        }
        for (path, values) in values {
            let objects = values.map(\.object)
            Self.set(objects.count == 1 ? objects[0] : objects, at: path, in: record)
            Self.set(objects, at: path, in: arrays)
        }
    }

    /// - Parameter condition: A line's condition.
    /// - Returns: Did the event pass it? Only one that reads a listed key path or the event's type can be.
    func pass(_ condition: LineCondition) -> Bool {
        guard let text = condition.text, !condition.rulesOut else { return false }
        let listed = condition.keyPaths.filter { values[$0] != nil }
        guard !listed.isEmpty || condition.keyPaths.contains(where: typePaths.contains),
              let predicate = try? PredicateBridge.predicate(withFormat: PredicateText.comparingBooleans(text))
        else { return false }
        let object = condition.isAny ? arrays : record
        if (try? PredicateBridge.evaluate(predicate, with: object, variables: nil)) == true { return true }
        return listed.contains { values[$0]?.contains(where: \.isCut) == true }
    }

    /// Put an object at a key path in both records.
    ///
    /// - Parameters:
    ///   - object: The object.
    ///   - path: Its key path.
    private func set(_ object: Any, at path: String) {
        Self.set(object, at: path, in: record)
        Self.set(object is NSMutableDictionary ? NSMutableDictionary() : object, at: path, in: arrays)
    }

    /// Put an object at a key path in a record, making the dictionaries on the way. A key path through a value
    /// that's already there is left out.
    ///
    /// - Parameters:
    ///   - object: The object.
    ///   - path: Its key path.
    ///   - record: The record.
    private static func set(_ object: Any, at path: String, in record: NSMutableDictionary) {
        let keys = path.components(separatedBy: ".")
        var parent = record
        for key in keys.dropLast() {
            if parent[key] == nil { parent[key] = NSMutableDictionary() }
            guard let next = parent[key] as? NSMutableDictionary else { return }
            parent = next
        }
        if let last = keys.last, !(parent[last] is NSMutableDictionary) { parent[last] = object }
    }
}
