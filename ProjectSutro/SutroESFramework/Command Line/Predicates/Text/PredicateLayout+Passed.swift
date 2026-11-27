//
//  PredicateLayout+Passed.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/22/26.
//

import Foundation


// MARK: - The lines an event passed
public extension PredicateLayout {
    /// The lines whose condition an event passed, which Event Facts' Indicators popover marks.
    ///
    /// In the rule an event matched, every condition joined with `AND` held, or the rule wouldn't have matched. So
    /// each is passed, a `!=` and a `NOT` too, as is each line of a group joined with `AND` whose own conditions are.
    /// A group under `NOT` has the lines that open and close it passed, not the lines it rules out.
    ///
    /// Of conditions joined with `OR` only one need hold, so each is evaluated on what the hit says the event had
    /// (``IndicatorHit/matched``), and on the event's type. One is passed when it reads a key path the hit lists, or
    /// the event's type, and holds there. A hit lists only what an event has, so there a line that only rules
    /// something out is never passed: one that starts with `NOT`, one in a group under `NOT`, and a `!=` a value
    /// outside `ANY`. `ANY ... !=` lists the string it found, so it's checked on that. An array's `.@count` is
    /// checked on the size the hit lists at that key path. A value the hit cut short
    /// (``IndicatorMatchedField/Value/isCut``) can't always be checked, so a line that reads one is passed.
    ///
    /// - Parameters:
    ///   - matched: What the hit lists.
    ///   - eventType: The event's type, such as `ES_EVENT_TYPE_NOTIFY_EXEC`, or `nil` when it isn't known.
    ///   - isWholeRule: Is the layout the whole rule the event matched? A sequence's step isn't, as another event
    ///     may have passed it, so each of its lines is evaluated on what the hit lists.
    /// - Returns: The passed lines' places in ``lines``.
    func passedLines(by matched: [IndicatorMatchedField], eventType: String? = nil,
                     isWholeRule: Bool = true) -> IndexSet {
        let facts = PassedFacts(matched, eventType: eventType)
        let conditions = lines.map { LineCondition($0.text) }
        let groups = LineGroups(conditions)
        var passed = IndexSet()
        for (index, condition) in conditions.enumerated() {
            let group = groups.group[index]
            let isPassed: Bool
            if isWholeRule, groups.conditionsHold(in: group) {
                isPassed = condition.text != nil || condition.opensNegatedGroup || groups.closesNegatedGroup(index)
            } else {
                isPassed = !groups.isUnderNot(group) && facts.pass(condition)
            }
            if isPassed { passed.insert(index) }
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
    /// What joins it to the line before: `AND` or `OR`, or `nil` for a group's first line or its `)`.
    let joiner: String?
    /// Does the line open a group, as `AND (` does?
    let opensGroup: Bool
    /// Does the line open a group under `NOT`, as `AND NOT (` does?
    let opensNegatedGroup: Bool
    /// Does the line close a group, as `)` does?
    let closesGroup: Bool
    /// Does it only rule something out: `NOT`, `NONE`, or `!=` anything but `nil` outside `ANY`?
    let rulesOut: Bool
    /// Does it compare any of an array's strings, with `ANY` or `SOME`?
    let isAny: Bool
    /// The key paths it reads.
    let keyPaths: [String]

    /// The words that join conditions, which start a line.
    private static let joiners: Set<String> = ["AND", "OR"]
    /// The symbols that join conditions, and the word each stands for.
    private static let symbols = [("&&", "AND"), ("||", "OR")]

    /// - Parameter line: A line's text, without its indentation.
    init(_ line: String) {
        var text = line.trimmingCharacters(in: .whitespaces)
        var joiner: String?
        for (symbol, word) in Self.symbols where text.hasPrefix(symbol) {
            text = String(text.dropFirst(symbol.count)).trimmingCharacters(in: .whitespaces)
            joiner = word
        }
        var tokens = PredicateText.tokens(in: text)
        if let first = tokens.first, first.range.location == 0, Self.joiners.contains(Self.word(first)) {
            joiner = Self.word(first)
            text = (text as NSString).substring(from: NSMaxRange(first.range)).trimmingCharacters(in: .whitespaces)
            tokens = PredicateText.tokens(in: text)
        }
        self.joiner = joiner
        let balance = Self.parentheses(in: text, outside: tokens)
        let opens = balance > 0 && text.hasSuffix("(")
        if opens { text = String(text.dropLast()).trimmingCharacters(in: .whitespaces) }
        let words = tokens.filter { [.keyword, .function].contains($0.kind) }.map(Self.word)
        opensGroup = opens
        opensNegatedGroup = opens && words.last == "NOT"
        closesGroup = balance < 0
        rulesOut = words.first == "NOT" || text.hasPrefix("!") || words.contains("NONE")
            || tokens.indices.contains { index in
                tokens[index].text.hasPrefix("!=")
                    && !(tokens.indices.contains(index + 1) && ["NIL", "NULL"].contains(Self.word(tokens[index + 1])))
                    && !(index >= 2 && ["ANY", "SOME"].contains(Self.word(tokens[index - 2])))
            }
        /// `SOME` isn't a keyword token, so every token is read.
        isAny = tokens.contains { ["ANY", "SOME"].contains(Self.word($0)) }
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


// MARK: - A layout's groups
/// The groups a layout's lines are in: the whole predicate, and each group in parentheses that breaks into lines. The
/// line that opens a group and the line that closes it are in the group around it, as the `AND` or `OR` that starts
/// the first is.
private struct LineGroups {
    /// A group of conditions.
    private struct Group {
        /// The group around it, or `nil` for the whole predicate.
        var parent: Int?
        /// Is it under `NOT`, as `NOT (` opens one?
        var isNegated = false
        /// Is any of its conditions joined with `OR`?
        var hasOr = false
    }

    /// The groups: the whole predicate first.
    private var groups = [Group()]
    /// Each line's group.
    private(set) var group: [Int] = []
    /// The group each line closes, by the line's place.
    private var closed: [Int: Int] = [:]

    /// - Parameter conditions: Each line's condition, in order.
    init(_ conditions: [LineCondition]) {
        var current = 0
        for (index, condition) in conditions.enumerated() {
            if condition.closesGroup, let parent = groups[current].parent {
                closed[index] = current
                current = parent
            }
            group.append(current)
            if condition.joiner == "OR" { groups[current].hasOr = true }
            if condition.opensGroup {
                groups.append(Group(parent: current, isNegated: condition.opensNegatedGroup))
                current = groups.count - 1
            }
        }
    }

    /// - Parameter group: A group.
    /// - Returns: Did each of its conditions hold, for an event that matched the predicate? They did when they're
    ///   joined with `AND`, and so are the conditions of every group around it, none of them under `NOT`.
    func conditionsHold(in group: Int) -> Bool {
        let found = groups[group]
        guard !found.hasOr else { return false }
        guard let parent = found.parent else { return true }
        return !found.isNegated && conditionsHold(in: parent)
    }

    /// - Parameter group: A group.
    /// - Returns: Is it, or a group around it, under `NOT`?
    func isUnderNot(_ group: Int) -> Bool {
        groups[group].isNegated || groups[group].parent.map(isUnderNot) == true
    }

    /// - Parameter line: A line's place.
    /// - Returns: Does the line close a group under `NOT`?
    func closesNegatedGroup(_ line: Int) -> Bool {
        closed[line].map { groups[$0].isNegated } == true
    }
}


// MARK: - What the event had
/// What a hit says an event had, as objects `NSPredicate` evaluates a line's condition on: the key paths the hit
/// lists with their values, the event's type under `es_event_type`, and its payload's key, such as `event.exec`. An
/// array's size, which a hit lists at its key path and `.@count`, is read by that whole key path.
private struct PassedFacts {
    /// Each listed key path's values, in the hit's order. Only an array's key path, which `ANY` read, has several.
    private var values: [String: [IndicatorMatchedField.Value]] = [:]
    /// The key paths that say the event's type: `es_event_type`, and its payload's.
    private var typePaths: Set<String> = []
    /// The event as a record, with one value at a key path that has one.
    private let record = NSMutableDictionary()
    /// The event as a record, with an array at every listed key path, as `ANY` reads one.
    private let arrays = NSMutableDictionary()
    /// Each array's size the hit lists, by its key path and `.@count`.
    private var counts: [String: Any] = [:]

    /// - Parameters:
    ///   - matched: What the hit lists.
    ///   - eventType: The event's type, or `nil`.
    init(_ matched: [IndicatorMatchedField], eventType: String?) {
        for field in matched { values[field.field, default: []].append(field.value) }
        if let eventType {
            let payload = "event." + EventNames.shortName(eventType)
            /// A Mac Monitor event's record has no `es_event_type`.
            if MacMonitorEvent(name: eventType) == nil {
                typePaths = ["es_event_type"]
                set(eventType as NSString, at: "es_event_type")
            }
            if PredicateEventTypes.payloads[payload] == eventType {
                typePaths.insert(payload)
                set(NSMutableDictionary(), at: payload)
            }
        }
        for (path, values) in values {
            let objects = values.map(\.object)
            /// A size isn't a key of the array's object, which key-value coding would read as the object's own count.
            if path.hasSuffix("." + RecordSchema.count) {
                counts[path] = objects[0]
                continue
            }
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
        let object = ListedRecord(condition.isAny ? arrays : record, counts: counts)
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


// MARK: - What's listed, as a record
/// The record of what a hit lists, which a line's condition is evaluated on. `NSPredicate` asks it for a key path at
/// once, so an array's size is found by its key path and `.@count`, and any other key path in the record's objects.
private final class ListedRecord: NSObject {
    /// The record's objects.
    private let record: NSDictionary
    /// Each array's size the hit lists, by its key path and `.@count`.
    private let counts: [String: Any]

    /// - Parameters:
    ///   - record: The record's objects.
    ///   - counts: Each array's size the hit lists, by its key path and `.@count`.
    init(_ record: NSDictionary, counts: [String: Any]) {
        self.record = record
        self.counts = counts
    }

    /// - Parameter key: A key at the top of the record.
    /// - Returns: Its value, or `nil`.
    override func value(forKey key: String) -> Any? {
        record.value(forKey: key)
    }

    /// - Parameter keyPath: A key path.
    /// - Returns: The listed size, for an array's `.@count`, or else the record's value there.
    override func value(forKeyPath keyPath: String) -> Any? {
        counts[keyPath] ?? record.value(forKeyPath: keyPath)
    }
}
