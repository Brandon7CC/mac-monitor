//
//  IndicatorFuzzTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Fuzzing
/// Random predicates into ``IndicatorCompiler`` and random sets into ``CompiledIndicators``: neither may trap. Each
/// random predicate that compiles is also evaluated on the synthetic corpus and the lineage trace and checked against
/// `NSPredicate` on each event's record, so the fuzzing is differential too. The seeds are fixed
/// (``SeededGenerator``), so a failure repeats.
final class IndicatorFuzzTests: XCTestCase {
    /// Predicates built from the grammar: compile or refuse, and agree with `NSPredicate` where they compile.
    func testRandomPredicatesCompileOrRefuseAndAgree() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + lineageTrace()
        var fuzzer = PredicateFuzzer(seed: 0x5EED_0001, messages: messages)
        var compiled = 0, refused = 0, matched = 0
        try withEventStore(messages) { _, stored in
            let records = try stored.map { event in
                try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(event)) as? NSDictionary)
            }
            var values = MessageValueCache()
            for _ in 0..<3_000 {
                let source = fuzzer.rule()
                guard case .success(let rule) = IndicatorCompiler.compile(source) else {
                    refused += 1
                    continue
                }
                compiled += 1
                let predicate = try StreamFilter.Predicate(source, for: .indicator)
                for (message, record) in zip(messages, records) {
                    let type = CompiledIndicators.eventType(of: message)
                    let mine = rule.types.contains(type) && rule.program.matches(message, eventType: type,
                                                                                 values: &values)
                    values.reset()
                    let expected = (try? predicate.evaluate(on: record)) == true
                    matched += mine ? 1 : 0
                    XCTAssertEqual(mine, expected, "\(source) on \(message.es_event_type)")
                }
            }
        }
        XCTAssertGreaterThan(compiled, 500)
        XCTAssertGreaterThan(refused, 300)
        XCTAssertGreaterThan(matched, 100)
    }

    /// Random sets under random budgets, from none to unlimited, on the corpus and on hostile execs: evaluating never
    /// traps, a budget's hits are among the unlimited ones, and every unlimited hit is a hit or undetermined, so a
    /// budget never hides one. Each list keeps to its limit.
    func testRandomBudgetsNeverHideAHit() throws {
        let corpus = try SyntheticCorpus.records().map(\.message) + lineageTrace()
        let messages = corpus + (try [AdversarialEvent.nonasciiCrafted, .max].map { try $0.message(self) })
        var fuzzer = PredicateFuzzer(seed: 0x5EED_0005, messages: corpus)
        var generator = SeededGenerator(seed: 0x5EED_0006)
        let limits = [0, 1, 2, 7, 64, 500, 4_000, 30_000, ScanBudget.eventLimit, .max]
        var undetermined = 0, hits = 0
        for _ in 0..<12 {
            let indicators = Indicator.defaults + (0..<20).map { _ in
                Indicator(name: "Fuzz", description: "", symbol: "star", color: .red, predicate: fuzzer.rule())
            }
            let compiled = CompiledIndicators(indicators)
            var values = MessageValueCache()
            for message in messages {
                values.scan.limit = .max
                let unlimited = compiled.evaluate(message, values: &values)
                values.scan.limit = limits.randomElement(using: &generator)!
                let budgeted = compiled.evaluate(message, values: &values)
                XCTAssertLessThanOrEqual(budgeted.hits.count, CompiledIndicators.hitLimit)
                XCTAssertLessThanOrEqual(budgeted.undetermined.count, CompiledIndicators.undeterminedLimit)
                let found = Set(budgeted.hits.map(\.id))
                XCTAssertTrue(found.isSubset(of: unlimited.hits.map(\.id)), message.es_event_type)
                if budgeted.undeterminedCount <= CompiledIndicators.undeterminedLimit,
                   budgeted.hits.count < CompiledIndicators.hitLimit {
                    let listed = found.union(budgeted.undetermined.map(\.hit.id))
                    XCTAssertTrue(Set(unlimited.hits.map(\.id)).isSubset(of: listed), message.es_event_type)
                }
                undetermined += budgeted.undeterminedCount
                hits += budgeted.hits.count
            }
        }
        XCTAssertGreaterThan(undetermined, 100)
        XCTAssertGreaterThan(hits, 100)
    }

    /// Text that's mostly noise: the compiler refuses it or compiles it, and never traps.
    func testRandomTextNeverTraps() {
        var generator = SeededGenerator(seed: 0x5EED_0002)
        let pieces = ["(", ")", "{", "}", " AND ", " OR ", "NOT ", "ANY ", "ALL ", "NONE ", "==", "!=", "<", ">=",
                      " LIKE[c] ", " IN ", " BEGINSWITH ", " MATCHES ", " BETWEEN ", "\"", "'", "\\", ",", "nil",
                      "es_event_type", #""ES_EVENT_TYPE_NOTIFY_EXEC""#, "target_path", "event.exec.env", "$x",
                      "SUBQUERY(", "FUNCTION(", "@count", "1e400", "9007199254740993", "-0", "YES", "\u{0}",
                      "\u{301}", "*", "?", "TRUEPREDICATE", "lowercase(", "."]
        for _ in 0..<5_000 {
            let text = (0..<Int.random(in: 1...24, using: &generator))
                .map { _ in pieces.randomElement(using: &generator)! }.joined()
            _ = IndicatorCompiler.compile(text)
            _ = IndicatorCompiler.compile(#"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND "# + text)
        }
    }

    /// Random sets: repeated identities, unknown and unnamed types, huge numbers, rules that are off, and predicates
    /// that don't compile. Every one is run or listed as a problem, and evaluating every event never traps.
    func testRandomSetsNeverTrap() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + lineageTrace()
        var fuzzer = PredicateFuzzer(seed: 0x5EED_0003, messages: messages)
        var generator = SeededGenerator(seed: 0x5EED_0004)
        let ids = (0..<8).map { _ in UUID() }
        var values = MessageValueCache()
        for _ in 0..<60 {
            let indicators = (0..<Int.random(in: 0...80, using: &generator)).map { _ -> Indicator in
                var indicator = Indicator(id: ids.randomElement(using: &generator)!, name: "Fuzz", description: "",
                                          symbol: "star", color: .red, predicate: fuzzer.rule(), isEnabled: Bool.random(using: &generator))
                if Int.random(in: 0..<8, using: &generator) == 0 {
                    indicator.predicate = [#"es_event_type == "ES_EVENT_TYPE_NOTIFY_NOPE""#, "target_path == 1e400",
                                           #"target_path == "x""#, ""].randomElement(using: &generator)!
                }
                return indicator
            }
            let compiled = CompiledIndicators(indicators)
            let enabledProblems = compiled.problems.filter { problem in
                indicators.contains { $0.id == problem.id && $0.isEnabled }
            }
            XCTAssertLessThanOrEqual(compiled.count + enabledProblems.count, indicators.count)
            XCTAssertEqual(compiled.count, indicators.filter { $0.isEnabled && $0.sensorProblem == nil }.count)
            for message in messages {
                XCTAssertLessThanOrEqual(compiled.hits(for: message, values: &values).count,
                                         CompiledIndicators.hitLimit)
            }
        }
    }
}


// MARK: - Random predicates
/// Makes random indicator predicates from a small grammar: a type check, then comparisons of served and unserved
/// fields, joined by `AND`, `OR` and `NOT`, with constants taken from the events' own values as well as hostile ones.
struct PredicateFuzzer {
    /// The random numbers.
    private var generator: SeededGenerator
    /// The event types to check for.
    private let types: [String]
    /// Each served field's string values on the events, and pieces of them.
    private let strings: [IndicatorField: [String]]

    /// Key paths besides the served ones, which the compiler refuses.
    static let unserved = ["process.pid", "event.exec.launched_by_parent.pid", "event.exec.env.@count",
                           "event.close.file_type"]
    /// Hostile and ordinary strings.
    static let hostile = ["", "a", "A", "/Users/", ".plist", "Re\u{301}sume\u{301}", "R\u{E9}sum\u{E9}", "\u{212A}",
                          "\u{17F}", "a\r\nb", "launchctl", "com.apple.", "Not supported", "MH_EXECUTE", "\u{1F600}"]
    /// Number constants, some refused.
    static let numbers = ["0", "1", "-1", "0.5", "YES", "NO", "1e400", "9007199254740993", "1000", "100000000"]

    /// - Parameters:
    ///   - seed: The seed.
    ///   - messages: The events whose values constants are taken from.
    init(seed: UInt64, messages: [Message]) {
        generator = SeededGenerator(seed: seed)
        types = Array(Set(messages.map(\.es_event_type))).sorted()
        var strings: [IndicatorField: [String]] = [:]
        for message in messages {
            for field in IndicatorField.allCases {
                if case .string(let value) = MessageValues.value(of: field, in: message) {
                    strings[field, default: []] += [String(value), String(value.prefix(4)), String(value.suffix(5))]
                }
            }
        }
        self.strings = strings
    }

    /// - Returns: A rule: a type check, maybe nested, and comparisons.
    mutating func rule() -> String {
        let type = IndicatorValue.literal(types.randomElement(using: &generator)![...])
        let check = Bool.random(using: &generator) ? "es_event_type == \(type)"
            : "es_event_type IN {\(type), \"ES_EVENT_TYPE_NOTIFY_EXIT\"}"
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

    /// - Returns: A comparison of a field, served or not, with a constant of its kind or not.
    private mutating func comparison() -> String {
        let field = IndicatorField.allCases.randomElement(using: &generator)!
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

