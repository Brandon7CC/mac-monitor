//
//  PredicateFuzzer.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation
@testable import SutroESFramework


// MARK: - Random predicates
/// Makes random indicator predicates from a small grammar: a type check, then comparisons of served and unserved
/// fields, joined by `AND`, `OR` and `NOT`, with constants taken from the events' own values as well as hostile ones.
/// Given a share for them, some comparisons are of a field with another field (``fieldComparison()``), and some of an
/// array's count (``countComparison()``).
struct PredicateFuzzer {
    /// The random numbers.
    private var generator: SeededGenerator
    /// The event types to check for.
    private let types: [String]
    /// Each served field's string values on the events, and pieces of them.
    private let strings: [IndicatorField: [String]]
    /// How many comparisons in four compare a field with another field: 0 keeps a seed's predicates as they were
    /// before field comparisons, and 4 makes every one a field comparison.
    private let fieldShare: Int
    /// How many comparisons in four compare an array's count, of those that don't compare two fields: 0 keeps a
    /// seed's predicates as they were before counts.
    private let countShare: Int
    /// The payload of the rule's event, such as `event.close`, whose arrays a count mostly reads.
    private var payload = ""

    /// Key paths besides the served ones, which the compiler refuses.
    static let unserved = ["process.pid", "event.exec.launched_by_parent.pid", "event.exec.env.@sum",
                           "event.close.file_type"]
    /// Hostile and ordinary strings.
    static let hostile = ["", "a", "A", "/Users/", ".plist", "Re\u{301}sume\u{301}", "R\u{E9}sum\u{E9}", "\u{212A}",
                          "\u{17F}", "a\r\nb", "launchctl", "com.apple.", "Not supported", "MH_EXECUTE", "\u{1F600}"]
    /// Number constants, some refused.
    static let numbers = ["0", "1", "-1", "0.5", "YES", "NO", "1e400", "9007199254740993", "1000", "100000000"]

    /// - Parameters:
    ///   - seed: The seed.
    ///   - messages: The events whose values constants are taken from.
    ///   - fieldShare: How many comparisons in four compare a field with another field.
    ///   - countShare: How many of the rest in four compare an array's count.
    init(seed: UInt64, messages: [Message], fieldShare: Int = 0, countShare: Int = 0) {
        generator = SeededGenerator(seed: seed)
        self.fieldShare = fieldShare
        self.countShare = countShare
        types = Array(Set(messages.map(\.es_event_type))).sorted()
        var strings: [IndicatorField: [String]] = [:]
        for message in messages {
            for field in IndicatorField.recordCases {
                if case .string(let value) = MessageValues.value(of: field, in: message) {
                    strings[field, default: []] += [String(value), String(value.prefix(4)), String(value.suffix(5))]
                }
            }
        }
        self.strings = strings
    }

    /// - Returns: A rule: a type check, maybe nested, and comparisons. A network flow's type check is its payload
    ///   test, since its record has no `es_event_type`.
    mutating func rule() -> String {
        let name = types.randomElement(using: &generator)!
        payload = "event." + EventNames.shortName(name)
        let type = IndicatorValue.literal(name[...]), exit = "\"ES_EVENT_TYPE_NOTIFY_EXIT\""
        let alone = Bool.random(using: &generator)
        let check = MacMonitorEvent(name: name) != nil
            ? (alone ? "\(payload) != nil" : "(\(payload) != nil OR es_event_type == \(exit))")
            : (alone ? "es_event_type == \(type)" : "es_event_type IN {\(type), \(exit)}")
        return check + " AND " + expression(depth: 0)
    }

    /// - Parameter depth: How deep it is.
    /// - Returns: An expression: a comparison, or a compound of more.
    private mutating func expression(depth: Int) -> String {
        switch depth > 2 ? 0 : Int.random(in: 0..<6, using: &generator) {
        case 1: return "(\(expression(depth: depth + 1)) AND \(expression(depth: depth + 1)))"
        case 2: return "(\(expression(depth: depth + 1)) OR \(expression(depth: depth + 1)))"
        case 3: return "NOT \(expression(depth: depth + 1))"
        default: return comparison()
        }
    }

    /// - Returns: A comparison of a field, served or not, with a constant of its kind or not, or with another field.
    private mutating func comparison() -> String {
        if fieldShare > 0, Int.random(in: 0..<4, using: &generator) < fieldShare { return fieldComparison() }
        if countShare > 0, Int.random(in: 0..<4, using: &generator) < countShare { return countComparison() }
        let field = IndicatorField.recordCases.randomElement(using: &generator)!
        let path = Int.random(in: 0..<12, using: &generator) == 0
            ? Self.unserved.randomElement(using: &generator)! : field.path
        let options = ["", "", "[c]", "[d]", "[cd]"].randomElement(using: &generator)!
        let any = field.kind == .strings || Int.random(in: 0..<20, using: &generator) == 0 ? "ANY " : ""
        let op = ["==", "!=", "BEGINSWITH", "ENDSWITH", "CONTAINS", "LIKE", "IN", "<", ">="]
            .randomElement(using: &generator)!
        let mismatched = Int.random(in: 0..<15, using: &generator) == 0
        let isNumber = (field.kind == .number || field.kind == .boolean) != mismatched
        let constant = isNumber ? number() : string(for: field, like: op == "LIKE")
        let written = op + (["<", ">="].contains(op) ? "" : options)
        guard op == "IN" else { return "\(any)\(path) \(written) \(constant)" }
        return "\(any)\(path) \(written) {\(constant), \(isNumber ? number() : string(for: field))}"
    }

    /// - Returns: A number constant, or `nil`.
    private mutating func number() -> String {
        Int.random(in: 0..<10, using: &generator) == 0 ? "nil" : Self.numbers.randomElement(using: &generator)!
    }

    /// - Parameters:
    ///   - field: The field it's compared with.
    ///   - like: Is it a `LIKE` pattern, which gets `*`s?
    /// - Returns: A string constant, quoted.
    private mutating func string(for field: IndicatorField, like: Bool = false) -> String {
        let pool = (strings[field] ?? []) + Self.hostile
        var string = pool.randomElement(using: &generator)!
        if like {
            string = ["*" + string + "*", string + "*", "*" + string, string, "*", "a*b?"]
                .randomElement(using: &generator)!
        }
        return IndicatorValue.literal(string[...])
    }
}


// MARK: - Random field comparisons
extension PredicateFuzzer {
    /// Record fields a field comparison's sides are drawn from besides the direct ones: numbers, strings, a Boolean,
    /// an array, an object, a launched-by parent's and the fields Mac Monitor writes as it stores an event.
    static let recordPaths = ["process.pid", "process.ppid", "process.euid", "process.audit_token.euid",
                              "process.audit_token.ruid", "event.exec.target.pid", "event.exec.target.ppid",
                              "event.exec.target.audit_token.pid", "process.cdhash", "event.exec.target.cdhash",
                              "process.euid_human", "event.exec.target.euid_human", "process.is_es_client",
                              "event.exec.launched_by_parent.pid", "event.exec.args", "process.executable",
                              "seq_num", "telemetry_version", "event.gatekeeper_user_override.sha256",
                              "event.gatekeeper_user_override.file.path", "mach_time", "version"]
    /// Every key path a side is drawn from, grouped by what it holds: strings, numbers and Booleans, and the rest.
    static let fieldPaths: (strings: [String], numbers: [String], others: [String]) = {
        var groups: (strings: [String], numbers: [String], others: [String]) = ([], [], [])
        for path in IndicatorField.recordCases.map(\.path) + recordPaths {
            switch kind(of: path) {
            case .string: groups.strings.append(path)
            case .number, .boolean: groups.numbers.append(path)
            case .strings, nil: groups.others.append(path)
            }
        }
        return groups
    }()

    /// - Parameter path: A key path.
    /// - Returns: What its value is, or `nil` for one the Security Extension doesn't read.
    private static func kind(of path: String) -> IndicatorField.Kind? {
        if let field = IndicatorField(path: path) { return field.kind }
        guard case .kind(let kind) = RecordSchema.lookup(path) else { return nil }
        return kind
    }

    /// - Returns: A comparison of a field with another field: mostly two of one kind with an operator they take, and
    ///   otherwise anything, with `ANY` now and then.
    mutating func fieldComparison() -> String {
        let (strings, numbers, others) = Self.fieldPaths
        let kind = Int.random(in: 0..<8, using: &generator)
        let paths = kind < 4 ? strings : kind < 7 ? numbers : others
        let left = paths.randomElement(using: &generator)!
        let mismatched = Int.random(in: 0..<6, using: &generator) == 0
        let right = (mismatched ? strings + numbers + others : paths).randomElement(using: &generator)!
        let taken = paths == numbers ? ["==", "!=", "<", "<=", ">", ">="] : ["==", "!=", "BEGINSWITH", "ENDSWITH"]
        let refused = ["CONTAINS", "LIKE", "IN", "MATCHES", "<", ">=", "BEGINSWITH"]
        let op = (Int.random(in: 0..<8, using: &generator) == 0 ? refused : taken).randomElement(using: &generator)!
        let options = ["", "", "", "[c]", "[d]", "[cd]"].randomElement(using: &generator)!
        let any = Int.random(in: 0..<24, using: &generator) == 0 ? "ANY " : ""
        return "\(any)\(left) \(op)\(paths == numbers && !mismatched ? "" : options) \(right)"
    }
}


// MARK: - Random counts
extension PredicateFuzzer {
    /// Every array's count a rule can compare: the record's arrays outside an array of objects.
    static let countPaths = RecordKeyPaths.shared.nodes.filter { $0.value.type == "array" && !$0.value.isInArray }
        .keys.filter { !$0.hasPrefix("indicators") }.sorted().map { $0 + ".@count" }
    /// Counts and aggregates the compiler refuses: an object's, a string's, a number's, the indicators', and
    /// aggregates other than `@count`.
    static let uncountable = ["event.close.yara_scan.@count", "process.signing_id.@count", "process.pid.@count",
                              "indicators.@count", "event.exec.args.@sum", "event.close.yara_scan.rules.@max"]

    /// - Returns: A count compared with a whole number, a set of them or another count, mostly with an operator a
    ///   number takes, and now and then with what's refused: `ANY`, a string's operator, `[c]`, or a constant that
    ///   isn't a whole number.
    mutating func countComparison() -> String {
        let left = countPath()
        let refused = Int.random(in: 0..<10, using: &generator) == 0
        let op = (refused ? ["CONTAINS", "BEGINSWITH", "==[c]", "LIKE"] : ["==", "!=", "<", "<=", ">", ">="])
            .randomElement(using: &generator)!
        let any = Int.random(in: 0..<20, using: &generator) == 0 ? "ANY " : ""
        switch Int.random(in: 0..<8, using: &generator) {
        case 0, 1:
            return "\(any)\(left) \(op) \(countPath())"
        case 2:
            return "\(any)\(left) \(op) " + ["nil", #""3""#, "0.5", "YES"].randomElement(using: &generator)!
        case 3:
            let set = (0..<2).map { _ in String(Int.random(in: 0...3, using: &generator)) }
            return "\(any)\(left) IN {\(set.joined(separator: ", "))}"
        default:
            return "\(any)\(left) \(op) \(Int.random(in: -1...4, using: &generator))"
        }
    }

    /// - Returns: A count's key path: mostly an array of the rule's event or of a process, now and then one of
    ///   another event, or one that's refused.
    private mutating func countPath() -> String {
        switch Int.random(in: 0..<10, using: &generator) {
        case 0:
            return Self.uncountable.randomElement(using: &generator)!
        case 1, 2:
            return Self.countPaths.randomElement(using: &generator)!
        default:
            let own = Self.countPaths.filter { $0.hasPrefix(payload + ".") || $0.hasPrefix("process.") }
            return own.randomElement(using: &generator)!
        }
    }
}
