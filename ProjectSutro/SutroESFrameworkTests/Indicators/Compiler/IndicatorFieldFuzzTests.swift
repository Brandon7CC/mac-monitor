//
//  IndicatorFieldFuzzTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Fuzzing field comparisons
/// Random predicates that compare fields with fields (``PredicateFuzzer/fieldComparison()``): each that compiles agrees
/// with `NSPredicate` on every corpus event's record, Mac Monitor's own check of an indicator takes exactly the ones
/// the compiler does and refuses the rest in its words, and no budget hides a hit. The seeds are fixed
/// (``SeededGenerator``), so a failure repeats.
final class IndicatorFieldFuzzTests: XCTestCase {
    /// Rules of field comparisons, and of field comparisons mixed with constant ones, agree with `NSPredicate` on the
    /// synthetic corpus's and the lineage trace's records.
    func testRandomFieldComparisonsAgreeWithNSPredicate() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + lineageTrace()
        var fields = PredicateFuzzer(seed: 0x5EED_F001, messages: messages, fieldShare: 4)
        var mixed = PredicateFuzzer(seed: 0x5EED_F002, messages: messages, fieldShare: 2)
        var compiled = 0, refused = 0, matched = 0, compared = 0
        try withEventStore(messages) { _, stored in
            let records = try stored.map { event in
                try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(event)) as? NSDictionary)
            }
            var values = MessageValueCache()
            for round in 0..<3_000 {
                let source = round.isMultiple(of: 2) ? fields.rule() : mixed.rule()
                guard case .success(let rule) = IndicatorCompiler.compile(source) else {
                    refused += 1
                    continue
                }
                compiled += 1
                compared += rule.program.nodes.contains { $0.kind == .fieldCompare } ? 1 : 0
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
        XCTAssertGreaterThan(compiled, 1_000)
        XCTAssertGreaterThan(compared, 1_000)
        XCTAssertGreaterThan(refused, 200)
        XCTAssertGreaterThan(matched, 1_000)
    }

    /// Mac Monitor's own check of an indicator (``Indicator/problem``) takes a rule of field comparisons exactly when
    /// the compiler does, and refuses one in the words the compiler gives (``Indicator/sensorProblem``).
    func testTheAppRefusesExactlyWhatTheCompilerRefuses() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + lineageTrace()
        var fuzzer = PredicateFuzzer(seed: 0x5EED_F003, messages: messages, fieldShare: 4)
        var accepted = 0, refused = 0
        for _ in 0..<4_000 {
            let indicator = Indicator(name: "Fuzz", description: "", symbol: "star", color: .red,
                                      predicate: fuzzer.rule())
            let problem = indicator.problem, sensorProblem = indicator.sensorProblem
            XCTAssertEqual(problem, sensorProblem, indicator.predicate!)
            if problem == nil { accepted += 1 } else { refused += 1 }
        }
        XCTAssertGreaterThan(accepted, 1_000)
        XCTAssertGreaterThan(refused, 500)
    }

    /// Random sets of field comparisons under random budgets, on the corpus and on hostile execs: a budget's hits are
    /// among the unlimited ones, and every unlimited hit is a hit or undetermined, so a budget never hides one.
    func testRandomBudgetsNeverHideAFieldComparisonsHit() throws {
        let corpus = try SyntheticCorpus.records().map(\.message) + lineageTrace()
        let messages = corpus + (try [AdversarialEvent.nonasciiCrafted, .max].map { try $0.message(self) })
        var fuzzer = PredicateFuzzer(seed: 0x5EED_F004, messages: corpus, fieldShare: 3)
        var generator = SeededGenerator(seed: 0x5EED_F005)
        let limits = [0, 1, 2, 7, 64, 500, 4_000, 30_000, ScanBudget.eventLimit, .max]
        var undetermined = 0, hits = 0
        for _ in 0..<12 {
            let indicators = (0..<24).map { _ in
                Indicator(name: "Fuzz", description: "", symbol: "star", color: .red, predicate: fuzzer.rule())
            }
            let compiled = CompiledIndicators(indicators)
            var values = MessageValueCache()
            for message in messages {
                values.scan.limit = .max
                let unlimited = compiled.evaluate(message, values: &values)
                values.scan.limit = limits.randomElement(using: &generator)!
                let budgeted = compiled.evaluate(message, values: &values)
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
        /// A field comparison is cheap, and often decided by a missing side or two lengths for nothing, so few are
        /// refused.
        XCTAssertGreaterThan(undetermined, 0)
        XCTAssertGreaterThan(hits, 100)
    }
}
