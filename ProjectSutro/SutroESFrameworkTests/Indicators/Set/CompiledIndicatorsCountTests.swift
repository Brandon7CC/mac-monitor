//
//  CompiledIndicatorsCountTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Counting arrays on events
/// Pins how the Security Extension evaluates an array's `.@count`: as `NSPredicate` does on the event's export
/// record, the way the predicate search reads it, with the array, or the object holding it, missing, empty or full,
/// compared with constants and with another count. A hit on a count lists the key path, `.@count` and all, with the
/// array's size, and Event Facts marks the lines that size passes.
final class CompiledIndicatorsCountTests: XCTestCase {
    /// - Parameter payload: `close`, `rename` or `exec`.
    /// - Returns: Rules on its scan's counts, with constants and with each other, and one on the rules themselves,
    ///   which a count beside them mustn't hide.
    static func scanRules(_ payload: String) -> [String] {
        let scan = "event.\(payload).yara_scan"
        return ["\(scan).rules.@count > 0", "\(scan).rules.@count == 0", "\(scan).rules.@count != 1",
                "\(scan).rules.@count < 2", "\(scan).rules.@count >= 3", "\(scan).report_only.@count == 2",
                "\(scan).rules.@count IN {1, 3}", "\(scan).rules.@count == nil", "\(scan).rules.@count != nil",
                "\(scan).rules.@count > \(scan).report_only.@count",
                "\(scan).rules.@count <= \(scan).report_only.@count",
                "\(scan).rules.@count == \(scan).names.@count", "NOT \(scan).rules.@count > 1",
                "(\(scan).rules.@count > 2 OR \(scan).report_only.@count == 0)",
                #"ANY \#(scan).rules == "XProtect_B" AND \#(scan).rules.@count == 3"#]
            .map { "event.\(payload) != nil AND \($0)" }
    }

    /// Each rule on a close's, a rename's and an exec's scan counts, in one set, hits exactly the scans `NSPredicate`
    /// matches on their export records. Some pass and some fail on each scan, a missing scan's `nil` included.
    func testScanCountsAreNSPredicatesOnTheRecord() throws {
        for (type, payload) in [("ES_EVENT_TYPE_NOTIFY_CLOSE", "close"), ("ES_EVENT_TYPE_NOTIFY_RENAME", "rename"),
                                ("ES_EVENT_TYPE_NOTIFY_EXEC", "exec")] {
            let rules = Self.scanRules(payload)
            let indicators = rules.enumerated().map { ownIndicator("Count \($0)", $1) }
            let compiled = CompiledIndicators(indicators)
            XCTAssertEqual(compiled.problems.map(\.reason), [], payload)
            var values = MessageValueCache()
            var verdicts: [String: [Bool]] = [:]
            for scan in Self.countedScans {
                let line = try scannedRecord(type, scan: scan)
                let message = try TraceImporter.message(from: line)
                let record = try XCTUnwrap(JSONSerialization.jsonObject(with: line) as? NSDictionary)
                let evaluation = compiled.evaluate(message, values: &values)
                XCTAssertEqual(evaluation.undeterminedCount, 0)
                let hits = Set(evaluation.hits.map(\.id))
                for (rule, indicator) in zip(rules, indicators) {
                    let expected = try StreamFilter.Predicate(rule, for: .indicator).evaluate(on: record)
                    XCTAssertEqual(hits.contains(indicator.id), expected, "\(rule) on \(String(describing: scan))")
                    verdicts[rule, default: []].append(expected)
                }
            }
            let scan = "event.\(payload).yara_scan"
            func verdict(_ rule: String) -> [Bool]? { verdicts["event.\(payload) != nil AND \(scan).\(rule)"] }
            XCTAssertEqual(verdict("rules.@count == 0"), [false, true, false, false])
            XCTAssertEqual(verdict("rules.@count != 1"), [true, true, false, true])
            XCTAssertEqual(verdict("rules.@count == nil"), [true, false, false, false])
            XCTAssertEqual(verdict("rules.@count > \(scan).report_only.@count"), [false, false, true, true])
            XCTAssertEqual(verdict("rules.@count <= \(scan).report_only.@count"), [true, true, false, false])
        }
    }

    /// Every array of the synthetic corpus's events, compared with constants and with another array of its event,
    /// is `NSPredicate`'s on each event's export record.
    func testEveryArraysCountIsNSPredicatesOnTheCorpus() throws {
        let messages = try SyntheticCorpus.records().map(\.message) + countedScanMessages()
        let encoder = ExportEncoder(model: try XCTUnwrap(ExportEncoder.model))
        let records = try messages.map { message in
            try XCTUnwrap(JSONSerialization.jsonObject(with: encoder.line(for: message)) as? NSDictionary)
        }
        let rules = countRules(of: messages)
        XCTAssertGreaterThan(rules.count, 300)
        var values = MessageValueCache()
        var passed = 0
        for source in rules {
            let rule = try IndicatorCompiler.compile(source).get()
            let predicate = try StreamFilter.Predicate(source, for: .indicator)
            for (message, record) in zip(messages, records) {
                let type = CompiledIndicators.eventType(of: message)
                let mine = rule.types.contains(type)
                    && rule.program.matches(message, eventType: type, values: &values)
                values.reset()
                XCTAssertEqual(mine, try predicate.evaluate(on: record), "\(source) on \(message.es_event_type)")
                passed += mine ? 1 : 0
            }
        }
        XCTAssertGreaterThan(passed, 500)
    }

    /// A hit on a count lists the count's key path with the array's size, as a number comparison lists its number.
    /// Two counts compared list both. A `!=` lists nothing, as it says what the event doesn't have.
    func testAHitListsTheCountItPassed() throws {
        let scan = "event.close.yara_scan"
        let cases: [(String, [IndicatorMatchedField]?)] = [
            ("\(scan).rules.@count >= 3", [IndicatorMatchedField(field: "\(scan).rules.@count", value: .integer(3))]),
            ("\(scan).rules.@count > \(scan).report_only.@count", [
                IndicatorMatchedField(field: "\(scan).rules.@count", value: .integer(3)),
                IndicatorMatchedField(field: "\(scan).report_only.@count", value: .integer(2)),
            ]),
            ("\(scan).rules.@count != 1", nil),
        ]
        let message = try TraceImporter.message(from: try scannedRecord("ES_EVENT_TYPE_NOTIFY_CLOSE",
                                                                        scan: Self.countedScans[3]))
        for (rule, listed) in cases {
            let compiled = CompiledIndicators([ownIndicator("Counted", "event.close != nil AND \(rule)")])
            var values = MessageValueCache()
            let hit = try XCTUnwrap(compiled.hits(for: message, values: &values).first, rule)
            XCTAssertEqual(hit.matched, listed, rule)
        }
    }

    /// An exec's arguments and environment are counted where they're at hand, with no walk of the event. Rules on
    /// their counts cost an exec no allocation, as rules on its other direct fields don't. Counted only in an
    /// optimized build, which `test-performance.sh` makes. An unoptimized one allocates for its own reasons.
    func testAnExecsCountsAllocateNothing() throws {
        try XCTSkipUnless(PerformanceRun.isEnabled && AllocationCounter.isAvailable, PerformanceRun.skipReason)
        let compiled = CompiledIndicators(["event.exec.env.@count > 1000", "event.exec.args.@count > 1000"].map {
            ownIndicator($0, IndicatorCompilerCountTests.exec + $0)
        })
        XCTAssertEqual(compiled.problems.map(\.reason), [])
        let message = try nativeCopy(of: corpusExec())
        var values = MessageValueCache()
        XCTAssertTrue(compiled.hits(for: message, values: &values).isEmpty)
        XCTAssertEqual(AllocationCounter.counting { _ = compiled.hits(for: message, values: &values) }, 0)
    }

    /// What a hit on a count lists marks the lines its count passes in Event Facts, and only those, beside the
    /// strings an `ANY` of the same array listed.
    func testAHitsCountMarksTheLinesItPasses() throws {
        let scan = "event.close.yara_scan"
        let rule = "event.close != nil AND (\(scan).rules.@count >= 5 OR \(scan).rules.@count >= 3) "
            + #"AND (ANY \#(scan).rules == "XProtect_B" OR \#(scan).report_only.@count > \#(scan).rules.@count)"#
        let compiled = CompiledIndicators([ownIndicator("Counted", rule)])
        let message = try TraceImporter.message(from: try scannedRecord("ES_EVENT_TYPE_NOTIFY_CLOSE",
                                                                        scan: Self.countedScans[3]))
        var values = MessageValueCache()
        let hit = try XCTUnwrap(compiled.hits(for: message, values: &values).first)
        let layout = PredicateLayout(rule)
        let marked = layout.passedLines(by: try XCTUnwrap(hit.matched), eventType: "ES_EVENT_TYPE_NOTIFY_CLOSE")
        XCTAssertEqual(marked.map { layout.lines[$0].text }, [
            "event.close != nil",
            "OR \(scan).rules.@count >= 3",
            #"ANY \#(scan).rules == "XProtect_B""#,
        ])
    }
}


// MARK: - Rules on every array
extension CompiledIndicatorsCountTests {
    /// Rules on the count of every array of the record outside an array of objects, each with its event's type
    /// check: compared with 0, 1 and 2, and with the next array of the same event. The process's arrays are checked on
    /// every event type the messages have.
    ///
    /// - Parameter messages: The events, whose types a process's arrays are checked on.
    /// - Returns: The rules.
    func countRules(of messages: [Message]) -> [String] {
        let arrays = RecordKeyPaths.shared.nodes.filter { $0.value.type == "array" && !$0.value.isInArray }.keys
            .filter { !$0.hasPrefix("indicators") }.sorted()
        XCTAssertGreaterThan(arrays.count, 50)
        /// A network flow's record has no `es_event_type`, and no array outside its event.
        let types = Set(messages.compactMap(\.es_event_type)).filter { MacMonitorEvent(name: $0) == nil }.sorted()
            .map { "\"\($0)\"" }
        let everyType = "es_event_type IN {\(types.joined(separator: ", "))} AND "
        /// - Parameter path: An array's key path.
        /// - Returns: The type check of its event, `event.close != nil` for the close's.
        func type(of path: String) -> String {
            path.hasPrefix("event.") ? path.split(separator: ".").prefix(2).joined(separator: ".") + " != nil AND "
                : everyType
        }
        var rules: [String] = []
        for (index, path) in arrays.enumerated() {
            rules += ["== 0", ">= 1", "< 2", "!= 2"].map { type(of: path) + "\(path).@count \($0)" }
            guard let next = arrays.dropFirst(index + 1).first, type(of: next) == type(of: path) else { continue }
            rules += [">=", "==", "<"].map { type(of: path) + "\(path).@count \($0) \(next).@count" }
        }
        return rules
    }
}
