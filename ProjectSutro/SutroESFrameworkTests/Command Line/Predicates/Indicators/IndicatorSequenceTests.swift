//
//  IndicatorSequenceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Sequences
/// Pins how a sequence indicator reads, writes and is checked: as the indicators repository's pack ships one, saved in
/// a set, and refused for each way its steps, window and keys can't make a sequence.
final class IndicatorSequenceTests: XCTestCase {
    /// A sequence as a pack ships one: a Mach-O written, then made executable.
    static let packEntry = #"""
    {"color": "orange", "description": "A program wrote a Mach-O, which was then made executable.",
     "id": "9E8FCEF0-D13C-4264-95E6-C56D3C4ED9C6", "isEnabled": true, "kind": "sequence", "minEngine": "3.2.0",
     "name": "Written Mach-O made executable", "revision": 2,
     "sequence": {"atLeast": 2, "by": [], "order": "ordered", "within": 5, "steps": [
       {"join": [], "name": "write",
        "predicate": "event.close != nil AND event.close.modified == YES AND event.close.mach_o_type == \"MH_EXECUTE\""},
       {"join": [{"field": "target_path", "step": "write", "stepField": "target_path"}], "name": "executable",
        "predicate": "event.setmode != nil AND ANY event.setmode.mode_added == \"executable\""}]},
     "severity": "medium", "symbol": "doc.fill", "tableMarks": ["dot"], "tactic": "execution"}
    """#

    /// A pack's sequence entry reads as a sequence with its steps, joins, revision and minimum Mac Monitor, has no
    /// predicate on one event, and can be used.
    func testPackEntryReads() throws {
        let indicator = try JSONDecoder().decode(Indicator.self, from: Data(Self.packEntry.utf8))
        let sequence = try XCTUnwrap(indicator.sequence)
        XCTAssertNil(indicator.predicate)
        XCTAssertNil(indicator.eventPredicate)
        XCTAssertEqual(indicator.rule.kind, .sequence)
        XCTAssertEqual(sequence.order, .ordered)
        XCTAssertEqual(sequence.within, 5)
        XCTAssertEqual(sequence.atLeast, 2)
        XCTAssertEqual(sequence.steps.map(\.name), ["write", "executable"])
        let join = IndicatorSequence.Join(field: "target_path", step: "write", stepField: "target_path")
        XCTAssertEqual(sequence.steps[1].join, [join])
        XCTAssertEqual(indicator.revision, 2)
        XCTAssertEqual(indicator.minEngine, ReleaseVersion(3, 2, 0))
        XCTAssertEqual(indicator.tactic, .execution)
        XCTAssertTrue(indicator.isSupported)
        XCTAssertNil(indicator.problem)
        XCTAssertNil(indicator.sensorProblem)
        XCTAssertEqual(indicator.rule.predicates.map(\.step), ["write", "executable"])
    }

    /// A sequence writes its kind and sequence, and no predicate, and reads back the same. A rule on one event writes
    /// no kind, as builds before sequences wrote it.
    func testRoundTrip() throws {
        let indicator = try JSONDecoder().decode(Indicator.self, from: Data(Self.packEntry.utf8))
        let data = try JSONEncoder().encode(indicator)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["kind"] as? String, "sequence")
        XCTAssertNil(object["predicate"])
        XCTAssertEqual(try JSONDecoder().decode(Indicator.self, from: data), indicator)
        let event = Indicator(name: "One", description: "", symbol: "star", color: .red, predicate: "event.exec != nil")
        let eventObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(event)) as? [String: Any]
        XCTAssertNil(eventObject?["kind"])
        XCTAssertNil(eventObject?["revision"])
        XCTAssertNil(eventObject?["minEngine"])
    }

    /// A sequence without `by`, `atLeast` or a step's `join` reads them as none, every step, and none.
    func testDefaults() throws {
        let json = #"{"order": "unordered", "within": 60, "steps": [{"name": "a", "predicate": "x == 1"}]}"#
        let sequence = try JSONDecoder().decode(IndicatorSequence.self, from: Data(json.utf8))
        XCTAssertEqual(sequence.by, [])
        XCTAssertEqual(sequence.atLeast, 1)
        XCTAssertEqual(sequence.steps[0].join, [])
    }

    /// A saved set keeps a sequence someone added, and writes it back as it was.
    func testSavedSetKeepsASequence() throws {
        let indicator = try JSONDecoder().decode(Indicator.self, from: Data(Self.packEntry.utf8))
        let saved = SavedIndicators([indicator] + Indicator.defaults)
        let read = try XCTUnwrap(SavedIndicators(data: try XCTUnwrap(saved.encoded())))
        XCTAssertEqual(read.undecodableCount, 0)
        XCTAssertEqual(read.indicators.first, indicator)
    }

    /// Each way a sequence's shape is wrong is refused, and says why: too long a `by` or too many joins too, or a
    /// path or join named twice, which would make each event's keys and each chain's values grow without bound.
    func testShapeProblems() {
        let exec = #"event.exec != nil"#
        let step = { (name: String, join: [IndicatorSequence.Join]) in
            IndicatorSequence.Step(name: name, predicate: exec, join: join)
        }
        let tied = [IndicatorSequence.Join(field: "target_path", step: "a", stepField: "target_path")]
        let joins = { (fields: Range<Int>) in
            fields.map { IndicatorSequence.Join(field: "target_path", step: "a", stepField: "process.f\($0)") }
        }
        let pair = [step("a", []), step("b", [])]
        let cases: [(IndicatorSequence, String)] = [
            (.init(order: .ordered, within: 5, steps: [step("a", [])]), "2 to 8 steps"),
            (.init(order: .ordered, within: 0, steps: [step("a", []), step("b", tied)]), "a second to a day"),
            (.init(order: .ordered, within: 86_401, steps: [step("a", []), step("b", tied)]), "a second to a day"),
            (.init(order: .ordered, within: 5, steps: [step("a", []), step("B", tied)]), "lowercase letter"),
            (.init(order: .ordered, within: 5, steps: [step("a", []), step("a", tied)]), "Two steps"),
            (.init(order: .ordered, within: 5, steps: [step("a", []), step("b", [])]), "Nothing ties"),
            (.init(order: .ordered, within: 5, steps: [step("a", tied), step("b", [])]), "isn't a step before"),
            (.init(order: .unordered, within: 5, steps: [step("a", []), step("b", [])]), "needs by"),
            (.init(order: .unordered, within: 5, by: ["process.audit_token.pid"],
                   steps: [step("a", []), step("b", tied)]), "only an ordered"),
            (.init(order: .ordered, within: 5, atLeast: 1, steps: [step("a", []), step("b", tied)]), "atLeast"),
            (.init(order: .ordered, within: 5, by: ["process.audit_token.pid"], atLeast: 2,
                   steps: [step("a", []), step("b", []), step("c", [])]), "needs every step"),
            (.init(order: .ordered, within: 5, by: ["process.nothing_here"], steps: [step("a", []), step("b", [])]),
             "process.nothing_here"),
            (.init(order: .ordered, within: 5, by: (0..<9).map { "process.f\($0)" }, steps: pair),
             "at most 8 key paths"),
            (.init(order: .ordered, within: 5, by: ["process.audit_token.pid", "process.audit_token.pid"], steps: pair),
             "a key path twice"),
            (.init(order: .ordered, within: 5, steps: [step("a", []), step("b", joins(0..<9))]), "at most 8 joins"),
            (.init(order: .ordered, within: 5, steps: [step("a", []), step("b", tied + tied)]), "a join twice"),
            (.init(order: .ordered, within: 5, steps: [step("a", []), step("b", joins(0..<8)), step("c", joins(8..<16)),
                                                       step("d", joins(16..<17))]), "at most 16 fields"),
        ]
        for (sequence, words) in cases {
            let problem = sequence.problem ?? ""
            XCTAssertTrue(problem.contains(words), "\(problem) should say \(words)")
            XCTAssertEqual(sequence.sensorProblem, sequence.shapeProblem)
        }
    }

    /// An unordered sequence tied by `by` is fine with fewer than every step, and a step's unusable predicate is its
    /// problem, named by the step.
    func testUnorderedAtLeastAndStepProblems() {
        let exec = #"event.exec != nil"#
        let steps = ["a", "b", "c"].map { IndicatorSequence.Step(name: $0, predicate: exec) }
        let unordered = IndicatorSequence(order: .unordered, within: 60, by: ["process.audit_token.pid"], atLeast: 2,
                                          steps: steps)
        XCTAssertNil(unordered.problem)
        var broken = unordered
        broken.steps[1].predicate = "event.exec != nil AND"
        XCTAssertTrue(broken.problem?.hasPrefix("The step b: ") == true, broken.problem ?? "")
        XCTAssertTrue(broken.sensorProblem?.hasPrefix("The step b: ") == true, broken.sensorProblem ?? "")
    }

    /// A rule's text shows a sequence's order, window and keys, then each step on its own line.
    func testRuleText() throws {
        let indicator = try JSONDecoder().decode(Indicator.self, from: Data(Self.packEntry.utf8))
        let lines = indicator.rule.text.split(separator: "\n").map(String.init)
        XCTAssertEqual(lines.count, 3)
        XCTAssertEqual(lines[0], "ordered within 5s")
        XCTAssertTrue(lines[2].hasSuffix(" [target_path == write.target_path]"), lines[2])
        XCTAssertEqual(Indicator.Rule.event("x == 1").text, "x == 1")
    }
}
