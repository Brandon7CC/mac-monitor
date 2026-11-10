//
//  IndicatorIndexTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Indicator index
/// Pins ``IndicatorIndex`` and the anchors it's built from (``IndicatorAnchor``): which comparisons give an anchor and
/// which don't, what `AND`, `OR`, `NOT` and the event's type make of their children's, which rules an event is
/// evaluated against, and, on every event and random rules, that the rules it leaves out are never ones the event
/// matches.
final class IndicatorIndexTests: XCTestCase {
    /// The close type check every rule here starts with.
    static let close = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE" AND "#

    /// String comparisons with an ASCII constant give anchors, folded constants lowered; the rest give none.
    func testComparisonsGiveTheirAnchors() throws {
        let path = IndicatorField.targetPath
        XCTAssertEqual(try need(#"target_path ENDSWITH[c] ".PLIST""#), [anchor(path, .suffix, ".plist", true)])
        XCTAssertEqual(try need(#"target_path BEGINSWITH "/A""#), [anchor(path, .prefix, "/A")])
        XCTAssertEqual(try need(#"target_path == "/a""#), [anchor(path, .exact, "/a")])
        XCTAssertEqual(try need(#"target_path ==[cd] "/A""#), [anchor(path, .exact, "/a", true)])
        XCTAssertEqual(try need(#"target_path CONTAINS[d] "/x/""#), [anchor(path, .contains, "/x/")])
        XCTAssertEqual(try need(#"event.close.mach_o_type IN {"MH_EXECUTE", "MH_DYLIB"}"#),
                       [anchor(.closeMachOType, .exact, "MH_EXECUTE"), anchor(.closeMachOType, .exact, "MH_DYLIB")])
        XCTAssertEqual(try need(#"target_path LIKE[c] "/Users/*/X""#), [anchor(path, .prefix, "/users/", true)])
        XCTAssertEqual(try need(#"target_path LIKE "*/x.plist""#), [anchor(path, .suffix, "/x.plist")])
        XCTAssertEqual(try need(#"target_path LIKE "abc""#), [anchor(path, .exact, "abc")])
        for unanchored in [#"target_path LIKE "*x*""#, #"target_path != "/a""#, #"NOT target_path == "/a""#,
                           #"target_path ENDSWITH "\#u{E9}""#, "event.close.modified == YES", "target_path == nil"] {
            XCTAssertEqual(try need(unanchored), ["unconstrained"], unanchored)
        }
    }

    /// `AND` needs what its cheapest anchored child needs, and `OR` one of what every child needs, or nothing the
    /// index checks when a child needs nothing.
    func testAndTakesItsCheapestChildAndOrTakesEvery() throws {
        let path = IndicatorField.targetPath
        XCTAssertEqual(try need(#"target_path CONTAINS "/x/" AND target_path BEGINSWITH "/a""#),
                       [anchor(path, .prefix, "/a")])
        XCTAssertEqual(try need(#"event.close.modified == YES AND target_path CONTAINS "/x/""#),
                       [anchor(path, .contains, "/x/")])
        XCTAssertEqual(try need(#"(target_path ENDSWITH "a" OR target_path BEGINSWITH "b")"#),
                       [anchor(path, .suffix, "a"), anchor(path, .prefix, "b")])
        XCTAssertEqual(try need(#"(target_path ENDSWITH "a" OR event.close.modified == YES)"#), ["unconstrained"])
    }

    /// A comparison of the event's type decides its branch: one for another type is left out of an `OR`, and makes
    /// an `AND` impossible.
    func testTheEventTypeDecidesBranches() throws {
        let rename = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_RENAME""#
        let source = #"(es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE" AND target_path ENDSWITH ".a") OR ("#
            + rename + #" AND target_path ENDSWITH ".b")"#
        let program = try compile(source)
        let path = IndicatorField.targetPath
        XCTAssertEqual(describe(program, type(ES_EVENT_TYPE_NOTIFY_CLOSE)), [anchor(path, .suffix, ".a")])
        XCTAssertEqual(describe(program, type(ES_EVENT_TYPE_NOTIFY_RENAME)), [anchor(path, .suffix, ".b")])
        XCTAssertEqual(describe(program, type(ES_EVENT_TYPE_NOTIFY_EXEC)), ["never"])
        XCTAssertEqual(try need("NOT " + rename), ["unconstrained"])
    }

    /// An event is evaluated against the rules whose literals it has, whole values only when it's all of it, and
    /// those that need nothing; a value that isn't ASCII has every anchor of its field. A `LIKE` is evaluated when
    /// the value starts with its pattern's first literal, whether or not the rest matches.
    func testAnEventIsEvaluatedAgainstTheRulesItCouldMatch() throws {
        let compiled = CompiledIndicators([#"target_path ENDSWITH[c] ".plist""#, #"target_path BEGINSWITH "/Library/""#,
                                           #"target_path == "/exact""#, #"target_path CONTAINS[c] "/caches/""#,
                                           "event.close.modified == YES", #"target_path LIKE[c] "/Users/*/X/*""#]
            .map { indicator(Self.close + $0) })
        let expected: [(String, [Int])] = [
            ("/Users/a/X.PLIST", [0, 4, 5]), ("/Library/Foo/Caches/x", [1, 3, 4]), ("/exact", [2, 4]),
            ("/exact/more", [4]), ("/LIBRARY/x", [4]), ("/USERS/a/x/b", [4, 5]), ("", [4]),
            ("/x/\u{E9}.plist", [0, 1, 2, 3, 4, 5]),
        ]
        var values = MessageValueCache()
        for (path, positions) in expected {
            let message = try close(path)
            XCTAssertEqual(compiled.candidates(for: message, values: &values), positions, path)
        }
        var message = try close("/Users/a/X.PLIST")
        message.event_type = Int(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue)
        XCTAssertEqual(compiled.candidates(for: message, values: &values), [])
    }

    /// Hundreds of copies of the shipped close rules, on a close of a file none of them names, are none of them
    /// evaluated, and a type's candidates past 4,096 rules still come out in order.
    func testManyRulesAreLeftOutAtOnce() throws {
        var values = MessageValueCache()
        let copies = try distinctRules(500, for: ES_EVENT_TYPE_NOTIFY_CLOSE)
        let written = try close("/private/var/folders/x/T/written.txt")
        XCTAssertEqual(CompiledIndicators(copies).candidates(for: written, values: &values), [])
        let wide = CompiledIndicators((0..<5_000).map { indicator(Self.close + #"target_path ENDSWITH "/w\#($0)""#) })
        XCTAssertEqual(wide.candidates(for: try close("/a/w4999"), values: &values), [4_999])
        XCTAssertEqual(wide.hits(for: try close("/a/w4999"), values: &values).count, 1)
    }

    /// On every event the tests have, against the shipped rules, their doubled copies and 2,048 path rules, the
    /// index leaves out no rule an event matches.
    func testNoMatchingRuleIsLeftOutOnTheCorpus() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + allFixtureMessages() + lineageTrace()
            + macathEvents().flatMap(\.messages)
        let paths = [ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CREATE]
            .flatMap { pathRules(2_048, for: $0) }
        for indicators in [Indicator.defaults, try distinctRules(200), paths] {
            assertNothingLeftOut(CompiledIndicators(indicators), on: messages)
        }
    }

    /// Running out of the index's budget costs only pruning: at every allowance below what an event's index
    /// searches spend, up to 4,096 units, its candidates still include every rule it matches, for the shipped rules
    /// and their copies made distinct, and so do a hostile exec's at a few, for the shipped rules.
    func testRunningOutOfTheIndexBudgetOnlyCostsPruning() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + allFixtureMessages() + lineageTrace()
            + macathEvents().flatMap(\.messages)
        let hostile = try [AdversarialEvent.asciiCrafted, .nonascii, .max].map { try $0.message(self) }
        let sets = [CompiledIndicators(Indicator.defaults), CompiledIndicators(try distinctRules(200))]
        var tried = 0
        for compiled in sets {
            for message in messages {
                tried += assertCandidatesKeepMatches(compiled, message, at: nil)
            }
        }
        for message in hostile {
            tried += assertCandidatesKeepMatches(sets[0], message, at: [0, 1, 100, 4_096, ScanBudget.indexLimit])
        }
        XCTAssertGreaterThan(tried, messages.count * 2)
    }

    /// On random rules from the fuzzing grammar, with hostile constants (folded letters, NFD, the Kelvin sign), the
    /// set's hits are the rules that match, evaluated one by one, in order.
    func testRandomRulesHitAsEvaluatedOneByOne() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + lineageTrace()
        var fuzzer = PredicateFuzzer(seed: 0x5EED_1DE7, messages: messages)
        var rules: [(indicator: Indicator, rule: IndicatorCompiler.Rule)] = []
        while rules.count < 600 {
            let source = fuzzer.rule()
            if case .success(let rule) = IndicatorCompiler.compile(source) { rules.append((indicator(source), rule)) }
        }
        var values = MessageValueCache()
        var matched = 0
        for chunk in stride(from: 0, to: rules.count, by: 30).map({ rules[$0..<min($0 + 30, rules.count)] }) {
            let compiled = CompiledIndicators(chunk.map(\.indicator))
            for message in messages {
                let type = CompiledIndicators.eventType(of: message)
                let expected = chunk.filter { entry in
                    defer { values.reset() }
                    return entry.rule.types.contains(type)
                        && entry.rule.program.matches(message, eventType: type, values: &values)
                }.prefix(CompiledIndicators.hitLimit).map(\.indicator.id)
                let hits = compiled.hits(for: message, values: &values).map(\.id)
                XCTAssertEqual(hits, Array(expected), "\(message.es_event_type) \(message.target_path ?? "")")
                matched += hits.count
            }
        }
        XCTAssertGreaterThan(matched, 100)
    }
}


// MARK: - Helpers
extension IndicatorIndexTests {
    /// Check that every rule a set has an event match is among the event's candidates.
    ///
    /// - Parameters:
    ///   - compiled: The set.
    ///   - messages: The events.
    func assertNothingLeftOut(_ compiled: CompiledIndicators, on messages: [Message],
                              file: StaticString = #filePath, line: UInt = #line) {
        var values = MessageValueCache()
        var evaluated = 0, rules = 0
        for message in messages {
            let candidates = Set(compiled.candidates(for: message, values: &values))
            let matching = compiled.matchingPositions(for: message, values: &values)
            XCTAssertTrue(matching.isSubset(of: candidates), "\(message.es_event_type) \(message.target_path ?? "")",
                          file: file, line: line)
            evaluated += candidates.count
            rules += compiled.candidates(forType: CompiledIndicators.eventType(of: message))
        }
        XCTAssertLessThan(evaluated, rules, "The index left nothing out", file: file, line: line)
    }

    /// Check that an event's candidates include every rule it matches at each index allowance.
    ///
    /// - Parameters:
    ///   - compiled: The set.
    ///   - message: The event.
    ///   - allowances: The index's allowances, or `nil` for each from 0 to what its searches spend, at most 4,096.
    /// - Returns: How many allowances it tried.
    func assertCandidatesKeepMatches(_ compiled: CompiledIndicators, _ message: Message, at allowances: [Int]?,
                                     file: StaticString = #filePath, line: UInt = #line) -> Int {
        var values = MessageValueCache()
        let matching = compiled.matchingPositions(for: message, values: &values)
        _ = compiled.candidates(for: message, values: &values, budget: 0)
        let unsearched = values.lastEventUnits
        _ = compiled.candidates(for: message, values: &values)
        let spent = values.lastEventUnits - unsearched
        let tried = allowances ?? Array(0...min(spent, 4_096))
        for allowance in tried {
            let candidates = compiled.candidates(for: message, values: &values, budget: allowance * 8)
            XCTAssertTrue(matching.isSubset(of: candidates), "\(message.es_event_type) at \(allowance)",
                          file: file, line: line)
        }
        return tried.count
    }

    /// - Parameter source: A comparison, after the close type check.
    /// - Returns: What the rule needs of a close (``describe(_:_:)``).
    /// - Throws: A failure when it doesn't compile.
    func need(_ source: String) throws -> [String] {
        describe(try compile(Self.close + source), type(ES_EVENT_TYPE_NOTIFY_CLOSE))
    }

    /// - Parameters:
    ///   - program: A program.
    ///   - eventType: An event type's number.
    /// - Returns: What the program needs of an event of the type: `never`, `unconstrained`, or each anchor
    ///   (``anchor(_:_:_:_:)``).
    func describe(_ program: IndicatorProgram, _ eventType: Int) -> [String] {
        switch program.necessity(eventType: eventType) {
        case .never: return ["never"]
        case .unconstrained: return ["unconstrained"]
        case .anyOf(let anchors):
            return anchors.map { anchor in
                let bytes = program.bytes[Int(anchor.offset)..<Int(anchor.offset + anchor.length)]
                return self.anchor(anchor.field, anchor.shape, String(decoding: bytes, as: UTF8.self), anchor.folding)
            }
        }
    }

    /// - Parameter source: A predicate.
    /// - Returns: Its program.
    /// - Throws: A failure when it doesn't compile.
    func compile(_ source: String) throws -> IndicatorProgram {
        switch IndicatorCompiler.compile(source) {
        case .success(let rule): return rule.program
        case .failure(let problem): throw BenchmarkFailure("\(source): \(problem)")
        }
    }

    /// - Parameters:
    ///   - field: Its field.
    ///   - shape: Where its bytes are.
    ///   - text: Its bytes.
    ///   - folding: Folded?
    /// - Returns: An anchor, described.
    func anchor(_ field: IndicatorField, _ shape: IndicatorAnchor.Shape, _ text: String,
                _ folding: Bool = false) -> String {
        "\(field) \(shape)\(folding ? "[c]" : "") \(text)"
    }

    /// - Parameter type: A type.
    /// - Returns: Its number.
    func type(_ type: es_event_type_t) -> Int {
        Int(type.rawValue)
    }

    /// - Parameter predicate: Its predicate.
    /// - Returns: An indicator of someone's own.
    func indicator(_ predicate: String) -> Indicator {
        Indicator(name: "Test", description: "", symbol: "star", color: .blue, predicate: predicate)
    }

    /// - Parameter path: Its target's path.
    /// - Returns: The synthetic corpus's first close, modified, of the path.
    /// - Throws: The error making the corpus, or a failure when it has no close.
    func close(_ path: String) throws -> Message {
        var message = try XCTUnwrap(SyntheticCorpus.records().map(\.message)
            .first { $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE" })
        message.target_path = path
        if case .close(var close) = message.event {
            close.modified = true
            message.event = .close(close)
        }
        return message
    }
}
