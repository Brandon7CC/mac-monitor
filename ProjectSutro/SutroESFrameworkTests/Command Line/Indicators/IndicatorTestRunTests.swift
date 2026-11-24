//
//  IndicatorTestRunTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Testing a pack
/// Pins `macmonitor indicators test`, which the indicators repository's CI runs: what each case and benign capture
/// comes to on recorded events, what fails the run, its exit status, and its command line. The fixtures are the
/// repository's own for Quarantine attribute removed: `xattr -d` deleting the quarantine attribute, and another.
final class IndicatorTestRunTests: XCTestCase {
    /// The quarantine fixture: one record, which Quarantine attribute removed matches.
    private static let quarantine = "indicator-test-xattr-quarantine.jsonl"
    /// The near miss: one record of another attribute deleted, which it doesn't.
    private static let other = "indicator-test-xattr-other.jsonl"
    /// Quarantine attribute removed's identity.
    private static let removed = UUID(uuidString: "6D4D0F1D-0000-4000-8000-000000000003")!

    /// A pack with Quarantine attribute removed, and any more entries.
    ///
    /// - Parameter more: More indicator entries, as JSON objects.
    /// - Returns: The pack.
    private func pack(_ more: [[String: Any]] = []) throws -> IndicatorPack {
        let removed: [String: Any] = [
            "id": Self.removed.uuidString, "revision": 2, "minEngine": "3.2.0", "name": "Quarantine attribute removed",
            "description": "", "severity": "low", "isEnabled": false, "symbol": "xmark.shield", "color": "red",
            "tableMarks": ["dot"], "tactic": "defenseImpairment",
            "predicate": #"event.deleteextattr != nil AND event.deleteextattr.extattr ENDSWITH "apple.quarantine""#,
        ]
        let file: [String: Any] = [
            "format": IndicatorExchange.format, "version": 2,
            "pack": ["sequence": 3, "published": "2026-11-15T09:35:16Z", "commit": String(repeating: "b", count: 40),
                     "min_engine": "3.2.0", "core": [], "retired": []],
            "indicators": [removed] + more,
        ]
        return try IndicatorPack.decode(try JSONSerialization.data(withJSONObject: file))
    }

    /// A plan's case, as JSON.
    private func testCase(_ events: String, _ expect: String, id: UUID = removed, count: Int? = nil,
                          records: [Int]? = nil) -> [String: Any] {
        var entry: [String: Any] = ["id": id.uuidString, "name": "A case", "events": events, "expect": expect]
        entry["count"] = count
        entry["records"] = records
        return entry
    }

    /// Run a plan on a pack, with the plan's paths in the fixtures folder.
    ///
    /// - Parameters:
    ///   - cases: The cases, as JSON.
    ///   - corpus: The captures, as JSON.
    ///   - pack: The pack: Quarantine attribute removed alone unless given.
    /// - Returns: The report.
    private func report(_ cases: [[String: Any]], corpus: [[String: Any]] = [], pack: IndicatorPack? = nil) throws
        -> IndicatorTestReport {
        let data = try JSONSerialization.data(withJSONObject: ["cases": cases, "corpus": corpus])
        let plan = try JSONDecoder().decode(IndicatorTestPlan.self, from: data)
        let base = try fixtureURL(Self.quarantine).deletingLastPathComponent()
        return IndicatorTestRun(pack: try pack ?? self.pack(), plan: plan, base: base).run()
    }

    /// A match case and a near miss pass, on an indicator that ships off, and the run exits 0.
    func testPassingCases() throws {
        let report = try report([testCase(Self.quarantine, "match", count: 1, records: [1]),
                                 testCase(Self.other, "none")])
        XCTAssertEqual(report.exit, .success)
        XCTAssertTrue(report.text.contains("  ok       Quarantine attribute removed: A case. It matched line 1."),
                      report.text)
        XCTAssertTrue(report.text.contains("No match in 1 record."), report.text)
        XCTAssertTrue(report.text.hasSuffix("2 of 2 cases passed. No benign capture was replayed. "
                                            + "Every indicator compiled.\n"), report.text)
        XCTAssertTrue(report.text.hasPrefix("Pack 3 from commit bbbbbbb: 1 indicators"), report.text)
    }

    /// Each way a case fails exits 65 and says why: a match where none was expected, none where one was, the wrong
    /// count, a line that had to match and didn't, and an indicator the pack hasn't.
    func testFailingCases() throws {
        let cases: [([String: Any], String)] = [
            (testCase(Self.quarantine, "none"), "It matched line 1."),
            (testCase(Self.other, "match"), "No match in 1 record."),
            (testCase(Self.quarantine, "match", count: 2), "It matched 1 record, not 2: line 1."),
            (testCase(Self.quarantine, "match", records: [1, 3]), "Line 3 didn't match. Line 1 did."),
            (testCase(Self.quarantine, "match", id: UUID()), "The pack has no indicator"),
        ]
        for (entry, words) in cases {
            let report = try report([entry])
            XCTAssertEqual(report.exit, .dataError, words)
            XCTAssertTrue(report.text.contains("FAILED"), report.text)
            XCTAssertTrue(report.text.contains(words), "\(report.text) should say \(words)")
        }
    }

    /// A sequence's case replays as the Security Extension runs it: the download's chmod completes the chain, and
    /// a recording with no download in it completes nothing.
    func testSequencesAreReplayed() throws {
        let sequence = try XCTUnwrap(try JSONSerialization.jsonObject(
            with: Data(IndicatorSequenceTests.packEntry.utf8)) as? [String: Any])
        let id = try XCTUnwrap(UUID(uuidString: sequence["id"] as? String ?? ""))
        let report = try report([testCase(SequenceEngineTests.download, "match", id: id, count: 1, records: [2]),
                                 testCase(Self.quarantine, "none", id: id)], pack: try pack([sequence]))
        XCTAssertEqual(report.exit, .success, report.text)
        XCTAssertTrue(report.text.contains("ok       Written Mach-O made executable: A case. It matched line 2."),
                      report.text)
        XCTAssertTrue(report.summary.hasPrefix("2 of 2 cases passed."), report.summary)
    }

    /// An indicator the Security Extension can't compile fails the run, whether or not a case tests it, and its
    /// cases fail.
    func testIndicatorsThatDontCompile() throws {
        let id = UUID()
        let untyped: [String: Any] = ["id": id.uuidString, "name": "Untyped", "predicate": "process.pid > 1"]
        let report = try report([testCase(Self.quarantine, "match"), testCase(Self.quarantine, "none", id: id)],
                                pack: try pack([untyped]))
        XCTAssertEqual(report.exit, .dataError)
        XCTAssertTrue(report.text.contains("Didn't compile\n  Untyped (\(id.uuidString)): It doesn't name its "
                                           + "event types"), report.text)
        XCTAssertTrue(report.text.contains("FAILED   Untyped: A case. It doesn't compile."), report.text)
        XCTAssertTrue(report.summary.hasSuffix("1 indicator doesn't compile."), report.summary)
    }

    /// A benign capture fails an indicator the cases test that hits it more often than its override allows, and
    /// passes one that doesn't.
    func testBenignCorpus() throws {
        let cases = [testCase(Self.other, "none")]
        let over = try report(cases, corpus: [["events": Self.quarantine, "allowed_hits": [:]]])
        XCTAssertEqual(over.exit, .dataError)
        XCTAssertTrue(over.text.contains("Quarantine attribute removed hit it once, 0 allowed."), over.text)
        let allowed = try report(cases, corpus: [["events": Self.quarantine,
                                                  "allowed_hits": [Self.removed.uuidString: 1]]])
        XCTAssertEqual(allowed.exit, .success, allowed.text)
        XCTAssertTrue(allowed.text.contains("1 record, none past an indicator's allowed hits."), allowed.text)
        XCTAssertTrue(allowed.summary.contains("1 of 1 benign capture passed."), allowed.summary)
    }

    /// A file that can't be read exits 66, and a record that isn't an event fails its case.
    func testFilesThatCantBeRead() throws {
        let missing = try report([testCase("no-such-file.jsonl", "none")])
        XCTAssertEqual(missing.exit, .noInput)
        XCTAssertTrue(missing.text.contains("“no-such-file.jsonl” can't be read"), missing.text)
        let directory = try makeTemporaryDirectory()
        let file = directory.appendingPathComponent("bad.jsonl")
        try Data("{\"not\": \"an event\"}\n".utf8).write(to: file)
        let plan = try JSONDecoder().decode(IndicatorTestPlan.self, from: Data(#"""
            {"cases": [{"id": "\#(Self.removed.uuidString)", "name": "Bad", "events": "bad.jsonl", "expect": "none"}]}
            """#.utf8))
        let bad = IndicatorTestRun(pack: try pack(), plan: plan, base: directory).run()
        XCTAssertEqual(bad.exit, .dataError)
        XCTAssertTrue(bad.text.contains("Line 1 of “bad.jsonl” can't be replayed"), bad.text)
    }

    /// The command reads its files from paths, exiting 66 for one that can't be read and 65 for one that isn't a
    /// pack or a plan, and writes the report.
    func testCommand() throws {
        let directory = try makeTemporaryDirectory()
        let planURL = directory.appendingPathComponent("plan.json")
        try Data(#"{"cases": []}"#.utf8).write(to: planURL)
        let notAPack = directory.appendingPathComponent("pack.json")
        try Data(#"{"format": "com.swiftlydetecting.indicators", "version": 1, "indicators": []}"#.utf8)
            .write(to: notAPack)
        let output = CapturedOutput()
        let missing = IndicatorTestRun.command(pack: directory.appendingPathComponent("none.json").path,
                                               plan: planURL.path, output: output)
        XCTAssertEqual(missing.failure?.exit, .noInput)
        let refused = IndicatorTestRun.command(pack: notAPack.path, plan: planURL.path, output: output)
        XCTAssertEqual(refused.failure?.exit, .dataError)
        XCTAssertTrue(refused.failure?.message.contains("not a pack") == true, refused.failure?.message ?? "")
        XCTAssertEqual(output.text, "")
    }

    /// `indicators test PACK --plan PLAN` parses, needs both, and needs neither root nor the Security Extension.
    func testCommandLine() throws {
        let parsed = try CommandLineParser.parse(["indicators", "test", "dist/pack.json", "--plan", "dist/plan.json"])
        XCTAssertEqual(parsed, .indicators(.test(pack: "dist/pack.json", plan: "dist/plan.json")))
        XCTAssertFalse(parsed.requiresRoot)
        XCTAssertNil(parsed.refusal(realUser: 501, effectiveUser: 0))
        XCTAssertTrue(try CommandLineParser.parse(["indicators", "list"]).requiresRoot)
        for arguments in [["indicators", "test", "pack.json"], ["indicators", "test", "--plan", "plan.json"],
                          ["indicators", "test", "a.json", "b.json", "--plan", "p.json"],
                          ["indicators", "test", "a.json", "--plan", "p.json", "--plan", "q.json"],
                          ["indicators", "test", "a.json", "--plan", "p.json", "--json"]] {
            XCTAssertThrowsError(try CommandLineParser.parse(arguments), arguments.joined(separator: " "))
        }
    }

    /// Lines, records and times read as words.
    func testCountingInWords() {
        XCTAssertEqual(IndicatorTestRun.lines([3]), "line 3")
        XCTAssertEqual(IndicatorTestRun.lines([3, 7]), "lines 3 and 7")
        XCTAssertEqual(IndicatorTestRun.lines([3, 7, 9]), "lines 3, 7 and 9")
        XCTAssertEqual(IndicatorTestRun.lines(Array(1...10)), "lines 1, 2, 3, 4, 5, 6, 7, 8 and 2 more")
        XCTAssertEqual(IndicatorTestRun.records(1), "1 record")
        XCTAssertEqual(IndicatorTestRun.times(1), "once")
        XCTAssertEqual(IndicatorTestRun.times(3), "3 times")
    }
}


// MARK: - Captured output
/// Standard output a test reads back.
private final class CapturedOutput: StreamOutput {
    /// What was written, as text.
    private(set) var text = ""

    /// - Parameter data: The bytes.
    func write(_ data: Data) throws {
        text += String(decoding: data, as: UTF8.self)
    }
}
