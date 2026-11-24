//
//  CompiledIndicatorsMatchedTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - What a hit matched
/// Pins what a hit says made it match (``IndicatorHit/matched``): the comparisons of its rule the event passed,
/// each with the value the event had, as the Security Extension stamps them and a record writes them.
final class CompiledIndicatorsMatchedTests: XCTestCase {
    /// - Parameters:
    ///   - predicate: A rule on execs.
    ///   - message: An exec.
    /// - Returns: What its hit says it matched, by field, or `nil` when it has no hit or lists nothing.
    /// - Throws: A failure when two listed share a field.
    private func matched(_ predicate: String, on message: Message) throws -> [String: IndicatorMatchedField.Value]? {
        let compiled = CompiledIndicators([ownIndicator("Mine", "event.exec != nil AND (\(predicate))")])
        XCTAssertEqual(compiled.problems.map(\.reason), [], predicate)
        var values = MessageValueCache()
        let hit = try XCTUnwrap(compiled.hits(for: message, values: &values).first, "No hit: \(predicate)")
        guard let fields = hit.matched else { return nil }
        XCTAssertEqual(Set(fields.map(\.field)).count, fields.count, "\(fields)")
        return Dictionary(uniqueKeysWithValues: fields.map { ($0.field, $0.value) })
    }

    /// An exec of curl by a program that isn't Apple's, with an environment and a long command line.
    private func exec() throws -> Message {
        var message = try corpusExec { exec in
            exec.target.executable?.path = "/usr/bin/curl"
            exec.env = ["HOME=/Users/a", "DYLD_INSERT_LIBRARIES=/tmp/x.dylib", "TERM=xterm"]
            exec.command_line = "curl " + String(repeating: "a", count: 1_000)
        }
        message.process.is_platform_binary = false
        return message
    }

    /// Every comparison of an `AND` the event passed is listed with the event's value: a string, a Boolean as one,
    /// and a number. A `!=` and anything under `NOT` say what the event doesn't have, and aren't.
    func testAnANDListsEachComparisonItPassed() throws {
        let rule = #"event.exec.target.executable.path ENDSWITH "/curl" AND process.is_platform_binary == NO "#
            + #"AND event.exec.target.executable.name != "wget" AND NOT event.exec.target.executable.name == "wget" "#
            + "AND process.audit_token.pid > 0"
        let pid = try XCTUnwrap(try exec().process.audit_token?.pid)
        XCTAssertEqual(try matched(rule, on: try exec()), [
            "event.exec.target.executable.path": .string("/usr/bin/curl"),
            "process.is_platform_binary": .boolean(false),
            "process.audit_token.pid": .integer(Int64(pid)),
        ])
    }

    /// An `OR` lists the branch that matched, not the ones that didn't. `IN` lists the value found.
    func testAnORListsTheBranchThatMatched() throws {
        let rule = #"event.exec.target.executable.name == "wget" OR "#
            + #"(event.exec.target.executable.name IN {"curl", "nc"} AND "#
            + #"event.exec.target.executable.path BEGINSWITH "/usr")"#
        XCTAssertEqual(try matched(rule, on: try exec()), [
            "event.exec.target.executable.name": .string("curl"),
            "event.exec.target.executable.path": .string("/usr/bin/curl"),
        ])
    }

    /// `ANY` lists the one string of the array that matched. A long value is cut to its first 256 characters.
    func testANYListsTheStringThatMatchedAndALongValueIsCut() throws {
        let any = try matched(#"ANY event.exec.env BEGINSWITH "DYLD_INSERT_LIBRARIES=""#, on: try exec())
        XCTAssertEqual(any, ["event.exec.env": .string("DYLD_INSERT_LIBRARIES=/tmp/x.dylib")])
        let long = try matched(#"event.exec.command_line BEGINSWITH "curl ""#, on: try exec())
        XCTAssertEqual(long, ["event.exec.command_line": .string("curl " + String(repeating: "a", count: 251))])
    }

    /// A rule that compares nothing but the event's type has nothing to list. A rule whose every comparison only
    /// rules something out has nothing either: a `!=` a value, `ANY ... !=`, and anything under `NOT`.
    func testARuleWithNothingToListSaysNone() throws {
        let compiled = CompiledIndicators([ownIndicator("Every exec", "event.exec != nil")])
        var values = MessageValueCache()
        XCTAssertNil(try XCTUnwrap(compiled.hits(for: try exec(), values: &values).first).matched)
        XCTAssertNil(try matched(#"event.exec.target.executable.name != "wget""#, on: try exec()))
        XCTAssertNil(try matched(#"ANY event.exec.env != "TERM=xterm""#, on: try exec()))
        XCTAssertNil(try matched(#"NOT ANY event.exec.env BEGINSWITH "LD_PRELOAD=""#, on: try exec()))
    }

    /// `!= nil` says the event has a value there, and lists it. A comparison of two fields lists both.
    func testAPresenceTestAndAFieldComparisonListTheirValues() throws {
        XCTAssertEqual(try matched("event.exec.command_line != nil", on: try exec()),
                       ["event.exec.command_line": .string("curl " + String(repeating: "a", count: 251))])
        let message = try exec()
        let two = try matched("process.audit_token.pid <= process.audit_token.euid "
                              + "OR process.audit_token.euid <= process.audit_token.pid", on: message)
        XCTAssertEqual(two?.keys.sorted(), ["process.audit_token.euid", "process.audit_token.pid"])
        XCTAssertNil(try matched("process.executable.path != event.exec.target.executable.path", on: message))
    }

    /// Saying what a hit matched has an allowance of its own. An `ANY` that spends more than half the environment's
    /// pool couldn't be run twice from it, so an explanation that shared the scan's would be refused. It's
    /// explained, and the scan says it spent what it did and was refused nothing.
    func testExplainingAHitHasItsOwnAllowance() throws {
        let rule = ownIndicator("Needle", #"event.exec != nil AND ANY event.exec.env == "NEEDLE=1""#)
        let compiled = CompiledIndicators([rule])
        var values = MessageValueCache()
        /// What `ANY` over this many variables spends, to size one that spends about 0.7 of the pool.
        let probe = 10_000
        _ = compiled.evaluate(try corpusExec { $0.env = Array(repeating: "A=1", count: probe) + ["NEEDLE=1"] },
                              values: &values)
        let count = probe * (ScanBudget.fieldLimit * 7 / 10) / max(values.lastEventUnits, 1)
        let message = try corpusExec { $0.env = Array(repeating: "A=1", count: count) + ["NEEDLE=1"] }
        let evaluation = compiled.evaluate(message, values: &values)
        XCTAssertGreaterThan(values.lastEventUnits, ScanBudget.fieldLimit / 2, "Twice wouldn't fit the pool")
        XCTAssertLessThanOrEqual(values.lastEventUnits, ScanBudget.fieldLimit)
        XCTAssertEqual(evaluation.hits.map(\.name), ["Needle"])
        XCTAssertEqual(evaluation.undetermined, [])
        XCTAssertEqual(evaluation.hits.first?.matched, [IndicatorMatchedField(field: "event.exec.env",
                                                                               value: .string("NEEDLE=1"))])
        XCTAssertEqual(values.scanExhaustedEvents, 0)
        XCTAssertEqual(values.lastEventRefused, 0)
    }

    /// The explanation of `ANY` runs `ANY` once, within its allowance, and leaves the lane's Foundation counts as
    /// the scan left them.
    func testExplainingANYLeavesTheCounts() throws {
        let message = try corpusExec { exec in
            exec.env = Array(repeating: "\u{E9}N", count: 40_000) + ["DYLD_INSERT_LIBRARIES=/tmp/x.dylib"]
        }
        let compiled = CompiledIndicators([ownIndicator("Inserted", "event.exec != nil AND "
                                                         + #"ANY event.exec.env BEGINSWITH "DYLD_INSERT_LIBRARIES=""#)])
        var values = MessageValueCache()
        let hit = try XCTUnwrap(compiled.evaluate(message, values: &values).hits.first)
        XCTAssertEqual(hit.matched, [IndicatorMatchedField(field: "event.exec.env",
                                                           value: .string("DYLD_INSERT_LIBRARIES=/tmp/x.dylib"))])
        XCTAssertEqual(values.foundation.stringsMade, 0)
        XCTAssertEqual(values.foundation.truncations, 0)
    }

    /// File > Open Trace reads what a hit matched as it was written: a number stays a number, a string of digits
    /// a string, and `true` a Boolean. An entry without its field or value is dropped with the list, not the hit.
    func testOpenTraceReadsWhatAHitMatchedAsWritten() throws {
        var hit = IndicatorHit(ownIndicator("Mine", "event.exec != nil"), isDefault: false,
                               evaluatedBy: .securityExtension)
        hit.matched = [IndicatorMatchedField(field: "process.audit_token.euid", value: .integer(0)),
                       IndicatorMatchedField(field: "process.audit_token.pid", value: .integer(42)),
                       IndicatorMatchedField(field: "process.signing_id", value: .string("501")),
                       IndicatorMatchedField(field: "event.exec.args", value: .string("true")),
                       IndicatorMatchedField(field: "process.is_platform_binary", value: .boolean(true))]
        var message = try exec()
        message.indicators = IndicatorVerdicts([hit])
        let record = try JSONEncoder().encode(message)
        XCTAssertEqual(try TraceImporter.message(from: record).indicators?.hits, [hit])

        var object = try XCTUnwrap(try JSONSerialization.jsonObject(with: record) as? [String: Any])
        var hits = try XCTUnwrap(object["indicators"] as? [[String: Any]])
        hits[0]["matched"] = [["field": "process.audit_token.pid"]]
        object["indicators"] = hits
        let broken = try TraceImporter.message(from: JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(broken.indicators?.hits.map(\.id), [hit.id], "The hit stands")
        XCTAssertNil(broken.indicators?.hits.first?.matched)
    }

    /// A hit writes what it matched in its record, and reads it back. One a build before wrote, without the key,
    /// reads as none.
    func testAHitsRecordListsWhatItMatched() throws {
        var hit = IndicatorHit(ownIndicator("Mine", "event.exec != nil"), isDefault: false,
                               evaluatedBy: .securityExtension)
        hit.matched = [IndicatorMatchedField(field: "event.exec.target.executable.path",
                                             value: .string("/usr/bin/curl")),
                       IndicatorMatchedField(field: "process.is_platform_binary", value: .boolean(false)),
                       IndicatorMatchedField(field: "process.audit_token.pid", value: .integer(42))]
        let data = try JSONEncoder().encode(hit)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let matched = try XCTUnwrap(object["matched"] as? [[String: Any]])
        XCTAssertEqual(matched.map { $0["field"] as? String }, hit.matched?.map(\.field))
        XCTAssertEqual(matched[0]["value"] as? String, "/usr/bin/curl")
        XCTAssertEqual(matched[1]["value"] as? Bool, false)
        XCTAssertEqual(matched[2]["value"] as? Int, 42)
        XCTAssertEqual(try JSONDecoder().decode(IndicatorHit.self, from: data), hit)
        var earlier = object
        earlier["matched"] = nil
        let decoded = try JSONDecoder().decode(IndicatorHit.self, from: JSONSerialization.data(withJSONObject: earlier))
        XCTAssertNil(decoded.matched)
        hit.matched = nil
        let none = try XCTUnwrap(try JSONSerialization.jsonObject(with: JSONEncoder().encode(hit)) as? [String: Any])
        XCTAssertTrue(none["matched"] is NSNull, "Written as null, as every key of a hit is")
    }

    /// A sequence's hit lists what the event that completed it matched, of the step it was.
    func testASequencesHitListsWhatCompletedIt() throws {
        let steps = [IndicatorSequence.Step(name: "curl", predicate: #"event.exec != nil AND "#
                                                + #"event.exec.target.executable.name == "curl""#),
                     IndicatorSequence.Step(name: "shell", predicate: #"event.exec != nil AND "#
                                                + #"event.exec.target.executable.name == "sh""#)]
        let sequence = IndicatorSequence(order: .unordered, within: 60, by: ["process.audit_token.pid"], atLeast: 2,
                                         steps: steps)
        let compiled = CompiledIndicators([sequenceIndicator(sequence)])
        XCTAssertEqual(compiled.problems.map(\.reason), [])
        var values = MessageValueCache()
        XCTAssertEqual(compiled.hits(for: try exec(), values: &values), [])
        let shell = try corpusExec { exec in
            exec.target.executable?.path = "/bin/sh"
        }
        let hit = try XCTUnwrap(compiled.hits(for: shell, values: &values).first)
        XCTAssertEqual(hit.matched, [IndicatorMatchedField(field: "event.exec.target.executable.name",
                                                           value: .string("sh"))])
    }
}
