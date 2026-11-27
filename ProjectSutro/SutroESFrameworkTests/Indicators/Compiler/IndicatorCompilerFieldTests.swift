//
//  IndicatorCompilerFieldTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Fields compared with fields
/// Pins what ``IndicatorCompiler`` takes and refuses of a field compared with another field
/// (``IndicatorDraft/FieldComparison``), each refusal with its own ``SensorProblem``, and that Mac Monitor's own check
/// of an indicator (``Indicator/problem``) takes the same ones and refuses the rest in the same words.
final class IndicatorCompilerFieldTests: XCTestCase {
    /// An exec's type check, which every rule here starts with.
    static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND "#

    /// Each operator a field compared with a field takes, on two strings, two numbers, a Boolean and a number, and
    /// record fields, with `[c]` and `[d]` on strings. Each program reads as its predicate.
    func testFieldComparisonsCompile() throws {
        let taken = ["event.exec.target.team_id != process.team_id", "target_path ==[cd] context",
                     "event.exec.target.signing_id BEGINSWITH[c] process.signing_id",
                     "process.executable.path ENDSWITH process.executable.name",
                     "event.exec.target.euid < event.exec.target.ruid", "process.pid <= process.ppid",
                     "event.exec.target.is_platform_binary == process.is_adhoc_signed",
                     "event.exec.target.is_adhoc_signed >= event.exec.target.euid",
                     "event.exec.launched_by_parent.pid > process.pid", "process.cdhash == event.exec.target.cdhash",
                     "es_event_type != context", "target_path == target_path"]
        for comparison in taken {
            let rule = try IndicatorCompiler.compile(Self.exec + comparison).get()
            XCTAssertEqual(rule.program.description, comparison)
            XCTAssertEqual(rule.program.nodes.map(\.kind), [.fieldCompare], comparison)
            XCTAssertNil(indicator(comparison).problem, comparison)
        }
        let rule = try IndicatorCompiler.compile(Self.exec + "event.exec.target.team_id != process.team_id").get()
        XCTAssertEqual(rule.program.fields, [.execTargetTeamID, .processTeamID])
        XCTAssertEqual(MemoryLayout<IndicatorProgram.Node>.stride, 16, "the right side's field fits beside the left's")
    }

    /// `CONTAINS`, `LIKE`, `IN` and `MATCHES` take constants alone, and `ANY` and `ALL` no key path on the right. Each
    /// refusal names the operators a field compared with a field takes.
    func testOperatorsAndModifiersAreRefused() {
        let refused = ["target_path CONTAINS context": "CONTAINS", "target_path LIKE[c] context": "LIKE",
                       "target_path IN context": "IN", "target_path MATCHES context": "MATCHES",
                       "ANY event.exec.env == process.team_id": "ANY", "ALL event.exec.args == context": "ALL"]
        for (comparison, word) in refused {
            guard case .unsupported(let reason) = problem(comparison) else {
                XCTFail("\(comparison): \(String(describing: problem(comparison)))")
                continue
            }
            XCTAssertTrue(reason.hasPrefix(word + " with a key path on its right, in "), reason)
            if word.count > 3 {
                XCTAssertTrue(reason.hasSuffix("takes ==, !=, <, <=, >, >=, BEGINSWITH or ENDSWITH"), reason)
            }
        }
        XCTAssertEqual(problem("target_path CONTAINS context")?.description, """
            The Security Extension doesn't evaluate CONTAINS with a key path on its right, in target_path CONTAINS \
            context: a key path compared with another takes ==, !=, <, <=, >, >=, BEGINSWITH or ENDSWITH.
            """)
    }

    /// An array on either side is refused, saying `ANY` compares one with constants alone and naming its `.@count`. A
    /// string compared with a number or a Boolean is refused naming both kinds, and so are strings ordered, a number
    /// searched and `[c]` or `[d]` on a number, as with constants.
    func testKindsAreRefused() {
        XCTAssertEqual(problem("event.exec.env == process.team_id"), .mismatchedTypes("""
            event.exec.env is an array, whose values ANY compares with constants alone and whose size is \
            event.exec.env.@count, in event.exec.env == process.team_id
            """))
        XCTAssertEqual(problem("process.team_id != event.exec.args"), .mismatchedTypes("""
            event.exec.args is an array, whose values ANY compares with constants alone and whose size is \
            event.exec.args.@count, in process.team_id != event.exec.args
            """))
        XCTAssertEqual(problem("target_path == process.pid"), .mismatchedTypes("""
            target_path is a string and process.pid a number, in target_path == process.pid
            """))
        XCTAssertEqual(problem("process.is_platform_binary != process.team_id"), .mismatchedTypes("""
            process.is_platform_binary is a Boolean and process.team_id a string, in process.is_platform_binary != \
            process.team_id
            """))
        XCTAssertEqual(problem("target_path < context"), .unsupported("ordering strings, in target_path < context"))
        XCTAssertEqual(problem("process.pid BEGINSWITH process.ppid"),
                       .mismatchedTypes("process.pid BEGINSWITH process.ppid"))
        XCTAssertEqual(problem("process.pid ==[c] process.ppid"),
                       .unsupported("[c] or [d] on a number, in process.pid ==[c] process.ppid"))
        XCTAssertEqual(problem("target_path ==[n] context"),
                       .unsupported("options other than [c] and [d], in target_path ==[n] context"))
    }

    /// The fields Mac Monitor writes as it stores an event stay refused on either side, as does an object, and a key
    /// path no record has is refused as it's read.
    func testUnservedFieldsAreRefusedOnEitherSide() {
        let stored = "Mac Monitor writes it as it stores the event, after the Security Extension evaluates it"
        XCTAssertEqual(problem("seq_num == process.pid"), .unservedKind("seq_num", stored))
        XCTAssertEqual(problem("process.pid != global_seq_num"), .unservedKind("global_seq_num", stored))
        XCTAssertEqual(problem("telemetry_version == version"), .unservedKind("telemetry_version", stored))
        XCTAssertEqual(problem("target_path == event.gatekeeper_user_override.file.path"),
                       .unservedKind("event.gatekeeper_user_override.file.path", stored))
        XCTAssertEqual(problem("event.gatekeeper_user_override.sha256 != context"),
                       .unservedKind("event.gatekeeper_user_override.sha256", stored))
        XCTAssertEqual(problem("process.executable == event.exec.target.executable"),
                       .unservedKind("process.executable", "it's an object"))
        XCTAssertEqual(problem("process.pid == process.executable.@count"), .uncountable("process.executable.@count"))
        guard case .unreadable = problem("target_path == process.no_such_key") else {
            return XCTFail("A key the record doesn't have is refused as it's read")
        }
    }

    /// Mac Monitor's own check of an indicator refuses each field comparison the compiler refuses, in its words, as
    /// Settings and `macmonitor` show it, and still takes a field compared with a function's result, which only the
    /// compiler refuses.
    func testTheAppRefusesInTheCompilersWords() throws {
        for comparison in ["target_path CONTAINS context", "ANY event.exec.env == process.team_id",
                           "event.exec.env == process.team_id", "target_path == process.pid", "target_path < context",
                           "seq_num == process.pid", "process.pid ==[c] process.ppid", "target_path MATCHES context",
                           "target_path IN context", "target_path ==[n] context", "NOT (context LIKE target_path)"] {
            let refused = indicator(comparison)
            XCTAssertNotNil(refused.problem, comparison)
            XCTAssertEqual(refused.problem, refused.sensorProblem, comparison)
        }
        let search = try StreamFilter.Predicate("target_path CONTAINS context", for: .search)
        XCTAssertFalse(search.relatesEvents)
        XCTAssertNil(indicator("target_path == lowercase(context)").problem)
        XCTAssertNotNil(indicator("target_path == lowercase(context)").sensorProblem)
    }
}


// MARK: - Helpers
extension IndicatorCompilerFieldTests {
    /// - Parameter comparison: A comparison, after the exec type check.
    /// - Returns: Why the rule doesn't compile, or `nil`.
    func problem(_ comparison: String) -> SensorProblem? {
        IndicatorCompiler.problem(with: Self.exec + comparison)
    }

    /// - Parameter comparison: A comparison, after the exec type check.
    /// - Returns: An indicator of someone's own with it.
    func indicator(_ comparison: String) -> Indicator {
        Indicator(name: "Test", description: "", symbol: "star", color: .blue, predicate: Self.exec + comparison)
    }
}
