//
//  CompiledIndicatorsParityTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Parity with Mac Monitor's matching
/// Pins the Security Extension's verdicts to Mac Monitor's: for every event the tests have, ``CompiledIndicators``
/// made from the shipped indicators names the same ones, in the same order, as ``IndicatorMatcher`` does on the event
/// as Mac Monitor stores it. With the Security Extension's scan budget, no event refuses a read or leaves an indicator
/// undetermined.
final class CompiledIndicatorsParityTests: XCTestCase {
    /// Every shipped indicator compiles for the Security Extension.
    func testEveryDefaultCompiles() {
        for indicator in Indicator.defaults {
            XCTAssertNil(indicator.sensorProblem, indicator.name)
        }
        let compiled = CompiledIndicators(Indicator.defaults)
        XCTAssertEqual(compiled.count, Indicator.defaults.count)
        XCTAssertEqual(compiled.problems, [])
    }

    /// The synthetic corpus, the fixtures and the lineage trace.
    func testHitsAreTheMatchersOnTheCorpus() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + allFixtureMessages() + lineageTrace()
        try assertParity(messages)
    }

    /// Every event the macath harnesses recorded on macOS 27, which make many of the shipped indicators match. Each
    /// shipped indicator but those no recording has an event for matches at least one.
    func testHitsAreTheMatchersOnTheMacathRecordings() throws {
        var matched: [UUID: Int] = [:]
        var events = 0
        for (name, messages) in try macathEvents() {
            try assertParity(messages, in: name).forEach { matched[$0.key, default: 0] += $0.value }
            events += messages.count
        }
        XCTAssertGreaterThan(events, 1_000)
        XCTAssertGreaterThanOrEqual(matched.count, Indicator.defaults.count / 2, "Few indicators matched any event")
    }

    /// The shipped indicators made distinct and doubled, as a large saved set has them, give the same verdicts: each
    /// indicator's hit after its copy's.
    func testDoubledDefaultsAreTheMatchers() throws {
        let copies = Indicator.defaults.map { indicator -> Indicator in
            var copy = indicator
            copy.id = UUID()
            copy.predicate = "(\(indicator.predicate)) AND NOT target_path == \"/nonexistent\""
            return copy
        }
        let messages = try SyntheticCorpus.records().map(\.message) + lineageTrace()
        try assertParity(messages, indicators: zip(Indicator.defaults, copies).flatMap { [$0, $1] })
    }
}


// MARK: - Checking parity
extension CompiledIndicatorsParityTests {
    /// Check the compiled set's hits on each event against the matcher's on it as stored.
    ///
    /// - Parameters:
    ///   - messages: The events.
    ///   - source: Where they're from, for failures.
    ///   - indicators: The indicators.
    /// - Returns: How many events each indicator matched.
    /// - Throws: The error storing an event.
    @discardableResult
    func assertParity(_ messages: [Message], in source: String = "", indicators: [Indicator] = Indicator.defaults,
                      file: StaticString = #filePath, line: UInt = #line) throws -> [UUID: Int] {
        let compiled = CompiledIndicators(indicators)
        var values = MessageValueCache()
        var matched: [UUID: Int] = [:]
        try withEventStore(messages) { _, stored in
            let matcher = IndicatorMatcher(indicators)
            for (message, event) in zip(messages, stored) {
                let expected = matcher.matches(event).map(\.id)
                let evaluation = compiled.evaluate(message, values: &values)
                let label = "\(source) \(message.es_event_type) \(message.target_path ?? "")"
                XCTAssertEqual(evaluation.hits.map(\.id), expected, label, file: file, line: line)
                XCTAssertEqual(evaluation.undetermined, [], label, file: file, line: line)
                XCTAssertEqual(values.lastEventRefused, 0, label, file: file, line: line)
                evaluation.hits.forEach { matched[$0.id, default: 0] += 1 }
            }
        }
        XCTAssertEqual(values.scanExhaustedEvents, 0, source, file: file, line: line)
        return matched
    }
}
