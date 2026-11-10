//
//  CompiledIndicatorsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Compiled indicators
/// Pins ``CompiledIndicators``: its bounds-checked index, `[]` against `nil`, the hit cap, the hits it makes once,
/// rules that are off or don't compile, and the predicates it shares and reuses, by their bytes.
final class CompiledIndicatorsTests: XCTestCase {
    /// A rule every exec matches.
    static let everyExec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    /// A type past the index, a negative one, `ES_EVENT_TYPE_LAST` and an event Mac Monitor doesn't model have no
    /// rules.
    func testTheIndexIsBoundsChecked() throws {
        let compiled = CompiledIndicators([indicator(Self.everyExec)])
        var values = MessageValueCache()
        var message = try exec()
        XCTAssertEqual(compiled.hits(for: message, values: &values).count, 1)
        for type in [10_000, -5, Int(ES_EVENT_TYPE_LAST.rawValue), Int.max, Int.min] {
            message.event_type = type
            XCTAssertEqual(compiled.hits(for: message, values: &values), [], "\(type)")
        }
        message = try exec()
        message.event = .unknown
        XCTAssertEqual(compiled.hits(for: message, values: &values), [])
    }

    /// Without a set nothing is evaluated (`nil`); with one, an event that matches nothing has `[]`.
    func testVerdictsAreNilOnlyWithoutASet() throws {
        var values = MessageValueCache()
        let message = try exec()
        XCTAssertNil(CompiledIndicators.verdicts(of: nil, for: message, values: &values))
        let none = CompiledIndicators([indicator(Self.everyExec + #" AND context == "no such context""#)])
        XCTAssertEqual(CompiledIndicators.verdicts(of: none, for: message, values: &values), [])
        XCTAssertEqual(CompiledIndicators.verdicts(of: CompiledIndicators([]), for: message, values: &values), [])
        let one = CompiledIndicators([indicator(Self.everyExec)])
        XCTAssertEqual(CompiledIndicators.verdicts(of: one, for: message, values: &values)?.count, 1)
    }

    /// A record lists the first 32 hits, and each event past it is counted in the lane's cache.
    func testHitsAreCappedAt32() throws {
        let indicators = (0..<40).map { _ in indicator(Self.everyExec) }
        let compiled = CompiledIndicators(indicators)
        XCTAssertEqual(compiled.count, 40)
        XCTAssertEqual(compiled.programCount, 1)
        XCTAssertEqual(compiled.compiledCount, 1)
        var values = MessageValueCache()
        let message = try exec()
        XCTAssertEqual(compiled.hits(for: message, values: &values).map(\.id), indicators.prefix(32).map(\.id))
        XCTAssertEqual(values.cappedEvents, 1)
        XCTAssertEqual(compiled.hits(for: message, values: &values).count, CompiledIndicators.hitLimit)
        XCTAssertEqual(values.cappedEvents, 2)
        let exactly = CompiledIndicators(Array(indicators.prefix(32)))
        var fresh = MessageValueCache()
        XCTAssertEqual(exactly.hits(for: message, values: &fresh).count, 32)
        XCTAssertEqual(fresh.cappedEvents, 0)
    }

    /// Each hit is the indicator's: its name, tactic, technique and severity, whether Mac Monitor ships it, and that
    /// the Security Extension evaluated it.
    func testHitsDescribeTheirIndicators() throws {
        let shipped = try XCTUnwrap(Indicator.defaults.first { $0.name == "Adhoc signed" })
        var own = indicator(Self.everyExec)
        own.severity = .high
        var values = MessageValueCache()
        var message = try exec()
        if case .exec(var exec) = message.event {
            exec.target.is_adhoc_signed = true
            message.event = .exec(exec)
        }
        let hits = CompiledIndicators([shipped, own]).hits(for: message, values: &values)
        XCTAssertEqual(hits.count, 2)
        XCTAssertEqual(hits.first, IndicatorHit(shipped, isDefault: true, evaluatedBy: .securityExtension))
        XCTAssertEqual(hits.first?.tactic, "Defense Evasion")
        XCTAssertEqual(hits.first?.tactic_id, "TA0005")
        XCTAssertEqual(hits.first?.technique, "T1553.002")
        XCTAssertEqual(hits.first?.severity, shipped.severity)
        XCTAssertEqual(hits.last, IndicatorHit(own, isDefault: false, evaluatedBy: .securityExtension))
        XCTAssertEqual(hits.last?.severity, .high)
    }

    /// Indicators that are off aren't run, and those that don't compile are listed by identity, repeats and those
    /// that are off too, with their reasons.
    func testOffAndRefusedIndicators() throws {
        var off = indicator(Self.everyExec)
        off.isEnabled = false
        var broken = indicator(#"target_path == "x""#)
        broken.isEnabled = false
        let unserved = indicator(Self.everyExec + " AND event.exec.env.@count > 1")
        let compiled = CompiledIndicators([off, broken, unserved, unserved])
        XCTAssertEqual(compiled.count, 0)
        XCTAssertEqual(compiled.problems.map(\.id), [broken.id, unserved.id, unserved.id])
        XCTAssertEqual(compiled.problems.first?.problem, .untyped)
        XCTAssertEqual(compiled.problems.last?.reason, SensorProblem.unservedField("event.exec.env.@count").description)
        var values = MessageValueCache()
        XCTAssertEqual(compiled.hits(for: try exec(), values: &values), [])
    }

    /// A set made from another compiles only the predicates that one didn't have, and the same programs result.
    func testCompiledPredicatesAreReused() throws {
        let first = CompiledIndicators(Indicator.defaults)
        XCTAssertEqual(first.compiledCount, Indicator.defaults.count)
        let added = indicator(Self.everyExec + #" AND context == "new""#)
        let second = CompiledIndicators(Indicator.defaults + [added], reusing: first)
        XCTAssertEqual(second.compiledCount, 1)
        XCTAssertEqual(second.count, Indicator.defaults.count + 1)
        var values = MessageValueCache()
        for message in try SyntheticCorpus.records().map(\.message) {
            XCTAssertEqual(first.hits(for: message, values: &values), second.hits(for: message, values: &values))
        }
    }

    /// Programs copied from one set's store into the next, in another order, with some gone and some new, and copied
    /// again into a third, give the same hits as the same rules compiled afresh.
    func testCopiedProgramsAreTheSameAsFreshOnes() throws {
        let doubled = Indicator.defaults + Indicator.defaults.map { indicator -> Indicator in
            var copy = indicator
            copy.id = UUID()
            copy.predicate = "(\(indicator.predicate)) AND NOT context == \"/nonexistent\""
            return copy
        }
        let first = CompiledIndicators(doubled)
        let reordered = Array(doubled.reversed().enumerated().filter { $0.offset % 3 != 0 }.map(\.element))
            + [indicator(Self.everyExec + #" AND context CONTAINS[c] "x""#)]
        let second = CompiledIndicators(reordered, reusing: first)
        XCTAssertEqual(second.compiledCount, 1)
        var generator = SeededGenerator(seed: 7)
        let shuffled = reordered.shuffled(using: &generator)
        let third = CompiledIndicators(shuffled, reusing: second)
        XCTAssertEqual(third.compiledCount, 0)
        let fresh = CompiledIndicators(shuffled)
        var values = MessageValueCache()
        let messages = try SyntheticCorpus.records().map(\.message) + lineageTrace()
        var hits = 0
        for message in messages {
            let expected = fresh.hits(for: message, values: &values)
            XCTAssertEqual(third.hits(for: message, values: &values), expected)
            hits += expected.count
        }
        XCTAssertGreaterThan(hits, 0)
    }

    /// Two indicators whose predicates differ only in how a constant is normalized (``CanonicalSpellings``), which
    /// Swift takes as one string, are two programs, as `==`, `!=` and `IN` compare bytes: for `==` and `IN` only the
    /// one spelled as the event is matches, and for `!=` only the other, in a set compiled afresh and in one made
    /// from another, either way round.
    func testCanonicallyEqualSourcesKeepTheirOwnPrograms() throws {
        XCTAssertEqual(CanonicalSpellings.nfc, CanonicalSpellings.nfd)
        var message = try exec()
        message.target_path = CanonicalSpellings.nfd
        for pair in CanonicalSpellings.pairs {
            let (composed, decomposed) = (pair.composed, pair.decomposed)
            let sets = [
                CompiledIndicators([composed, decomposed]),
                CompiledIndicators([composed, decomposed], reusing: CompiledIndicators([composed])),
                CompiledIndicators([decomposed, composed], reusing: CompiledIndicators([decomposed])),
                CompiledIndicators([decomposed, composed], reusing: CompiledIndicators([composed, decomposed])),
            ]
            for (index, compiled) in sets.enumerated() {
                var values = MessageValueCache()
                XCTAssertEqual(compiled.programCount, 2, "\(pair.format) set \(index)")
                XCTAssertEqual(compiled.hits(for: message, values: &values).map(\.id), [pair.hit],
                               "\(pair.format) set \(index)")
            }
            XCTAssertEqual(sets.map(\.compiledCount), [2, 1, 1, 0], pair.format)
        }
    }

    /// Matching nothing allocates nothing, and nor does stamping it, with no undetermined indicators, so the shipped
    /// indicators cost an unmatched event no memory: every event of the synthetic corpus that matches none, with
    /// native strings as a capture lane builds them, and whose fields are all ASCII (one that isn't is compared by
    /// Foundation, which makes strings). Counted only in an optimized build, which `test-performance.sh` makes: an
    /// unoptimized one allocates for its own reasons.
    func testMatchingNothingAllocatesNothing() throws {
        try XCTSkipUnless(PerformanceRun.isEnabled && AllocationCounter.isAvailable, PerformanceRun.skipReason)
        let compiled = CompiledIndicators(Indicator.defaults)
        var values = MessageValueCache()
        let quiet = try SyntheticCorpus.records().map { try nativeCopy(of: $0.message) }.filter { message in
            compiled.hits(for: message, values: &values).isEmpty && IndicatorField.allCases.allSatisfy { field in
                guard case .string(let string) = MessageValues.value(of: field, in: message) else { return true }
                return StringMatching.isASCII(string)
            }
        }
        XCTAssertGreaterThan(quiet.count, 50)
        for message in quiet {
            let allocations = AllocationCounter.counting { _ = compiled.hits(for: message, values: &values) }
            XCTAssertEqual(allocations, 0, message.es_event_type)
            var stamped = message
            let stamping = AllocationCounter.counting { compiled.stamp(&stamped, values: &values) }
            XCTAssertEqual(stamping, 0, "stamping \(message.es_event_type)")
            XCTAssertNil(stamped.indicators_undetermined)
        }
    }
}


// MARK: - Helpers
extension CompiledIndicatorsTests {
    /// - Parameter predicate: Its predicate.
    /// - Returns: An indicator of someone's own.
    func indicator(_ predicate: String) -> Indicator {
        Indicator(name: "Test", description: "", symbol: "star", color: .blue, predicate: predicate)
    }

    /// - Returns: The synthetic corpus's first exec.
    /// - Throws: The error making the corpus, or a failure when it has no exec.
    func exec() throws -> Message {
        try XCTUnwrap(SyntheticCorpus.records().map(\.message)
            .first { $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" })
    }
}
