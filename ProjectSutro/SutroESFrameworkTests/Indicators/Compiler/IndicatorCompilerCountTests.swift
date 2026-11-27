//
//  IndicatorCompilerCountTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/25/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Counting arrays
/// Pins what ``IndicatorCompiler`` takes and refuses of an array's `.@count`: the size of any array an event's record
/// has, a number compared with a number or with another field, and refused, saying why, on what isn't such an array,
/// under `ANY`, and as any other aggregate. Mac Monitor's own check of an indicator takes the same comparisons of two
/// fields and refuses the rest in the same words.
final class IndicatorCompilerCountTests: XCTestCase {
    /// An exec's type check, which rules on a process's arrays start with.
    static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND "#
    /// A close's, which rules on its scan start with.
    static let close = "event.close != nil AND "
    /// The arrays counted where they're at hand, as direct fields.
    static let direct = ["event.exec.args", "event.exec.env"]

    /// Every array of the record outside an array of objects is counted, of strings or of anything else, each with
    /// its event's type check. It's a number, which the program writes as the predicate does. An exec's arguments
    /// and environment are counted where they're at hand, as direct fields. Every other array is counted from the
    /// event's record. Only the indicators the Security Extension writes once it has evaluated an event aren't.
    func testEveryArrayOfTheRecordIsCounted() {
        let arrays = RecordKeyPaths.shared.nodes.filter { $0.value.type == "array" && !$0.value.isInArray }.keys
            .filter { !$0.hasPrefix("indicators") }.sorted()
        XCTAssertGreaterThan(arrays.count, 50)
        for path in arrays {
            let payload = path.split(separator: ".").prefix(2).joined(separator: ".")
            let type = path.hasPrefix("event.") ? "\(payload) != nil AND " : Self.exec
            let comparison = "\(path).@count >= 1"
            switch IndicatorCompiler.compile(type + comparison) {
            case .success(let rule):
                XCTAssertEqual(rule.program.description, comparison)
                XCTAssertEqual(rule.program.nodes.map(\.kind), [.compare], comparison)
                XCTAssertEqual(rule.program.fields.map(\.kind), [.number], comparison)
                XCTAssertEqual(rule.program.fields.map(\.isDirect), [Self.direct.contains(path)], comparison)
            case .failure(let problem):
                XCTFail("\(comparison): \(problem)")
            }
        }
    }

    /// An exec's arguments and environment are counted as direct fields, which cost what a small field does. So a
    /// count is read before the environment is searched, whatever order the rule names them in.
    func testAnExecsCountsAreReadFirst() throws {
        for path in Self.direct {
            XCTAssertEqual(IndicatorField(path: path + ".@count")?.isDirect, true, path)
        }
        let source = Self.exec + #"ANY event.exec.env CONTAINS "x" "#
            + "AND event.exec.args.@count > 9 AND event.exec.env.@count > 99"
        let rule = try IndicatorCompiler.compile(source).get()
        XCTAssertEqual(rule.program.description, "(event.exec.args.@count > 9 AND event.exec.env.@count > 99 "
                                                 + #"AND ANY event.exec.env CONTAINS "x")"#)
    }

    /// A count takes each operator a number does, `IN` and `nil` too, on a scan's arrays and on an exec's.
    func testACountTakesEveryNumbersOperator() throws {
        for path in ["event.close.yara_scan.rules", "event.close.yara_scan.report_only", "event.exec.args",
                     "event.exec.env", "event.exec.fds"] {
            let type = path.hasPrefix("event.close") ? Self.close : Self.exec
            for comparison in ["== 0", "!= 1", "< 2", "<= 3", "> 4", ">= 5", "IN {1, 2}", "== nil", "!= nil"] {
                let rule = try IndicatorCompiler.compile(type + "\(path).@count \(comparison)").get()
                XCTAssertEqual(rule.program.description, "\(path).@count \(comparison)")
            }
        }
    }

    /// Two arrays' counts of one record compare as two numbers, as any two fields have since 3.2, and a count and a
    /// number do too. Mac Monitor's own check takes them as well.
    func testCountsCompareAsTwoFields() throws {
        for comparison in ["event.close.yara_scan.rules.@count > event.close.yara_scan.report_only.@count",
                           "event.close.yara_scan.rules.@count == event.close.yara_scan.names.@count",
                           "process.audit_token.pid >= event.close.yara_scan.rules.@count",
                           "event.close.yara_scan.report_only.@count <= event.close.modified"] {
            let rule = try IndicatorCompiler.compile(Self.close + comparison).get()
            XCTAssertEqual(rule.program.description, comparison)
            XCTAssertEqual(rule.program.nodes.map(\.kind), [.fieldCompare], comparison)
            XCTAssertNil(indicator(Self.close + comparison).problem, comparison)
        }
    }

    /// `.@count` counts an array of the record alone. Of an object, a string, a number or an ancestor's list it's
    /// refused, saying so. An ancestor's list isn't in the record, so the predicate search couldn't check its count.
    func testWhatIsntAnArrayIsntCounted() {
        for path in ["event.close.yara_scan", "event.close.yara_scan.status", "process.signing_id", "process.pid"] {
            XCTAssertEqual(problem(Self.close + "\(path).@count > 0")?.description, """
                '\(path).@count' can't be counted: .@count counts an array of an event's record, and \(path) \
                isn't one.
                """)
        }
        for path in ["lineage.paths.@count", "launched_by.team_ids.@count", "lineage.paths.@sum"] {
            XCTAssertEqual(problem(Self.exec + "\(path) > 1"), .unreadable("""
                The indicator's predicate can't use '\(path)': an ancestor's list isn't counted or aggregated. \
                Records don't have a process's ancestors, so the predicate search couldn't check it. ANY compares \
                the list's values.
                """))
        }
    }

    /// The indicators a record lists are written once the Security Extension has evaluated the event, so they
    /// aren't counted, nor is what a hit lists.
    func testTheIndicatorsAreNotCounted() {
        let evaluated = "the Security Extension writes it once it has evaluated the event's indicators"
        for path in ["indicators.@count", "indicators_undetermined.@count", "indicators.matched.@count"] {
            XCTAssertEqual(problem(Self.exec + "\(path) > 0"), .unservedKind(path, evaluated))
        }
    }

    /// A count is one number: `ANY` of it, a string compared with it, a string's operator and `[c]` are refused. So
    /// is every aggregate but `@count`.
    func testACountIsComparedAsANumberAlone() {
        let any = problem(Self.exec + "ANY event.exec.args.@count > 1")
        XCTAssertEqual(any, .unsupported("ANY of event.exec.args.@count, which isn't an array, in "
                                         + "ANY event.exec.args.@count > 1"))
        for part in [#"event.exec.args.@count == "3""#, #"event.exec.args.@count BEGINSWITH "3""#,
                     "event.exec.args.@count == event.exec.target.signing_id"] {
            guard case .mismatchedTypes = problem(Self.exec + part) else {
                XCTFail("\(part): \(String(describing: problem(Self.exec + part)))")
                continue
            }
        }
        XCTAssertEqual(problem(Self.exec + "event.exec.args.@count ==[c] 1"),
                       .unsupported("[c] or [d] on a number, in event.exec.args.@count ==[c] 1"))
        for aggregate in ["@sum", "@avg", "@min", "@max"] {
            XCTAssertEqual(problem(Self.exec + "event.exec.args.\(aggregate) > 1"),
                           .unsupported("\(aggregate) of event.exec.args: it takes an array's .@count alone"))
        }
    }

    /// An array compared whole, without `ANY` or `.@count`, is refused, naming both.
    func testAnArrayComparedWholeNamesItsCount() {
        XCTAssertEqual(problem(Self.exec + #"event.exec.env == "x""#), .mismatchedTypes("""
            event.exec.env is an array, whose values ANY compares and whose size is event.exec.env.@count, in \
            event.exec.env == "x"
            """))
        XCTAssertEqual(problem(Self.exec + "event.exec.env == process.team_id"), .mismatchedTypes("""
            event.exec.env is an array, whose values ANY compares with constants alone and whose size is \
            event.exec.env.@count, in event.exec.env == process.team_id
            """))
        XCTAssertEqual(problem(Self.exec + "event.exec.fds == nil"), .unservedKind("event.exec.fds", """
            it's an array of other than strings, whose size is event.exec.fds.@count
            """))
    }

    /// An ancestor's list compared whole is refused without naming a `.@count`, which it doesn't have.
    func testAnAncestorsListComparedWholeNamesNoCount() {
        XCTAssertEqual(problem(Self.exec + #"lineage.paths == "x""#), .mismatchedTypes(
            #"lineage.paths is an array, whose values ANY compares, in lineage.paths == "x""#))
        XCTAssertEqual(problem(Self.exec + "launched_by.paths == process.team_id"), .mismatchedTypes("""
            launched_by.paths is an array, whose values ANY compares with constants alone, in launched_by.paths == \
            process.team_id
            """))
    }

    /// An index into an array is refused, pointing to `.@count`, which compiles.
    func testAnIndexIsRefusedForACountThatCompiles() throws {
        guard case .unreadable(let reason) = problem(Self.close + #"event.close.yara_scan.rules[LAST] == "x""#) else {
            return XCTFail("An index is refused as the predicate is read")
        }
        XCTAssertTrue(reason.hasSuffix("use ANY for an array's values and .@count for its size."), reason)
        XCTAssertNil(problem(Self.close + "event.close.yara_scan.rules.@count > 0"))
    }

    /// Mac Monitor's own check takes a count compared with a field when the compiler does, and refuses each one the
    /// compiler refuses, in its words.
    func testTheAppRefusesCountsInTheCompilersWords() {
        let taken = indicator(Self.exec + "event.exec.args.@count < event.exec.env.@count")
        XCTAssertNil(taken.problem)
        XCTAssertNil(taken.sensorProblem)
        for comparison in ["event.exec.args.@count == process.team_id", "event.exec.args.@count CONTAINS process.pid",
                           "ANY event.exec.args.@count == process.pid", "process.executable.@count == process.pid",
                           "event.exec.args.@sum == process.pid", "indicators.@count == process.pid",
                           "event.exec.args == event.exec.env.@count"] {
            let refused = indicator(Self.exec + comparison)
            XCTAssertNotNil(refused.problem, comparison)
            XCTAssertEqual(refused.problem, refused.sensorProblem, comparison)
        }
    }
}


// MARK: - Helpers
extension IndicatorCompilerCountTests {
    /// - Parameter source: A predicate.
    /// - Returns: Why it doesn't compile, or `nil`.
    func problem(_ source: String) -> SensorProblem? {
        IndicatorCompiler.problem(with: source)
    }

    /// - Parameter predicate: A predicate.
    /// - Returns: An indicator of someone's own with it.
    func indicator(_ predicate: String) -> Indicator {
        Indicator(name: "Test", description: "", symbol: "star", color: .blue, predicate: predicate)
    }
}
