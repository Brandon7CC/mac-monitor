//
//  IndicatorCompilerTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Refusals
/// Pins what ``IndicatorCompiler`` refuses, each with its own ``SensorProblem``, what it drops, and the programs it
/// makes.
final class IndicatorCompilerTests: XCTestCase {
    /// An exec's type check, which every rule here starts with.
    static let exec = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#

    /// Parentheses and braces past 32 deep are refused before anything parses them. Those in a string don't count.
    func testDeepNestingIsRefused() {
        let deep = String(repeating: "(", count: 33) + Self.exec + String(repeating: ")", count: 33)
        XCTAssertEqual(problem(deep), .tooDeep(33))
        let quoted = Self.exec + #" AND target_path == "((((((((((((((((((((((((((((((((((""#
        XCTAssertNil(problem(quoted))
        XCTAssertEqual(IndicatorCompiler.nestingDepth(of: #"a IN {{{"x"}}} AND (b == '(\'')"#), 3)
    }

    /// What Settings > Indicators can't use at all is refused with its reason: unreadable, too long, more than a
    /// comparison of values, or ending inside a string, which `NSPredicate`'s scanner would end the process on.
    func testUnusablePredicatesAreUnreadable() {
        for source in [Self.exec + " AND", String(repeating: "a", count: 4_097),
                       Self.exec + #" AND FUNCTION(target_path, 'length') == 1"#,
                       Self.exec + #" AND SUBQUERY(process_group, $e, $e.target_path == "x").@count > 0"#,
                       Self.exec + #" AND target_path == "x\"#, Self.exec + " AND target_path == `x"] {
            guard case .unreadable(let reason) = problem(source) else { return XCTFail(source) }
            XCTAssertFalse(reason.isEmpty)
        }
    }

    /// Every rule names its event types. One that names none, or only types this build doesn't know, is refused.
    func testRulesNameTheirTypes() {
        XCTAssertEqual(problem(#"target_path == "x""#), .untyped)
        XCTAssertEqual(problem(Self.exec + #" OR target_path == "x""#), .untyped)
        XCTAssertEqual(problem(#"es_event_type == "ES_EVENT_TYPE_NOTIFY_NOPE""#),
                       .unknownEventTypes(["ES_EVENT_TYPE_NOTIFY_NOPE"]))
        XCTAssertEqual(try rule(#"es_event_type IN {"ES_EVENT_TYPE_NOTIFY_NOPE", "ES_EVENT_TYPE_NOTIFY_EXIT"}"#).types,
                       [Int(ES_EVENT_TYPE_NOTIFY_EXIT.rawValue)])
        XCTAssertEqual(problem(Self.exec + #" AND es_event_type == "ES_EVENT_TYPE_NOTIFY_OPEN""#), .contradictoryTypes)
        XCTAssertEqual(problem("es_event_type IN {}"), .contradictoryTypes)
        XCTAssertFalse(SensorProblem.contradictoryTypes.description.hasSuffix(": ."))
    }

    /// Operators, modifiers and expressions the Security Extension doesn't evaluate.
    func testUnsupportedPartsAreRefused() {
        let parts = [#"target_path MATCHES "x""#: "MATCHES", #"ALL event.exec.env == "x""#: "ALL",
                     "event.exec.executable_age_ms BETWEEN {1, 2}": "BETWEEN",
                     #"lowercase(target_path) == "x""#: "lowercase", "target_path == context": "constants",
                     #"ANY target_path == "x""#: "ANY", #"target_path < "x""#: "ordering",
                     #"target_path ==[n] "x""#: "options", #"target_path BEGINSWITH nil"#: "nil",
                     "event.exec.executable_age_ms ==[c] 1": "[c] or [d]", #"target_path IN "abc""#: "IN"]
        for (part, word) in parts {
            guard case .unsupported(let reason) = problem(Self.exec + " AND " + part) else {
                XCTFail("\(part): \(String(describing: problem(Self.exec + " AND " + part)))")
                continue
            }
            XCTAssertTrue(reason.contains(word), "\(part): \(reason)")
        }
    }

    /// A key path the record doesn't have is refused, and so is one whose value can't be compared on its own: an
    /// object, or a value inside an array of objects. Any other key path of the record is read, the launched-by
    /// parent's included.
    func testUnservedPathsAreRefused() {
        if case .unreadable = problem(Self.exec + " AND process.no_such_key == 1") {} else {
            XCTFail("A key the record doesn't have is refused as it's read")
        }
        XCTAssertEqual(problem(Self.exec + " AND event.exec.env.@count > 1"), .unservedField("event.exec.env.@count"))
        XCTAssertEqual(problem(Self.exec + #" AND event.exec.target.executable == "x""#),
                       .unservedKind("event.exec.target.executable", "it's an object"))
        XCTAssertNil(problem(Self.exec + " AND process.pid == 1"))
        XCTAssertNil(problem(Self.exec + " AND event.exec.launched_by_parent.pid == 1"))
        XCTAssertNil(problem(Self.exec + #" AND ANY event.exec.args == "-c""#))
    }

    /// A string compared with a number, an array without `ANY`, and a string operator on a number.
    func testMismatchedTypesAreRefused() {
        for part in ["target_path == 1", #"event.exec.executable_age_ms == "1""#, #"event.exec.env == "x""#,
                     #"event.close.modified BEGINSWITH 1"#, #"target_path IN {"a", 1}"#] {
            guard case .mismatchedTypes = problem(Self.exec + " AND " + part) else {
                XCTFail("\(part): \(String(describing: problem(Self.exec + " AND " + part)))")
                continue
            }
        }
    }

    /// `LIKE` patterns of ASCII and `*` alone.
    func testLikePatternsAreASCIIAndStars() {
        for pattern in ["a?b", #"a\\*b"#, "R\u{E9}*"] {
            guard case .unsupportedPattern = problem(Self.exec + " AND target_path LIKE " + literal(pattern)) else {
                XCTFail(pattern)
                continue
            }
        }
        XCTAssertNil(problem(Self.exec + #" AND target_path LIKE[cd] "/Users/*/Library/*""#))
    }

    /// Numbers a `Double` can't hold exactly, too many nodes, and a constant over 1 KiB.
    func testLimitsAreRefused() {
        XCTAssertEqual(problem(Self.exec + " AND event.exec.executable_age_ms == 9007199254740993"),
                       .unrepresentableNumber("9007199254740993"))
        XCTAssertEqual(problem(Self.exec + " AND event.exec.executable_age_ms == 1e400"), .unrepresentableNumber("inf"))
        XCTAssertNil(problem(Self.exec + " AND event.exec.executable_age_ms == 9007199254740992"))
        XCTAssertNil(problem(Self.exec + " AND event.exec.executable_age_ms < 1e23"))
        /// `NSPredicate` reads a run of `OR`s as one node, so each is a `NOT` and its comparison: 401 nodes.
        let many = Self.exec + " AND (" + Array(repeating: #"NOT context=="""#, count: 200)
            .joined(separator: " OR ") + ")"
        XCTAssertEqual(problem(many), .tooManyNodes)
        let long = String(repeating: "x", count: IndicatorCompiler.maxConstantBytes + 1)
        XCTAssertEqual(problem(Self.exec + " AND target_path == " + literal(long)), .constantTooLong(1_025))
        XCTAssertNil(problem(Self.exec + " AND target_path == " + literal(String(long.dropFirst()))))
    }

    /// Each problem reads as a sentence, and ``Indicator/sensorProblem`` gives it.
    func testProblemsReadAsSentences() {
        let problems: [SensorProblem] = [.tooDeep(40), .untyped, .contradictoryTypes, .unknownEventTypes(["X"]),
                                         .unsupported("MATCHES"), .unservedField("process.pid"),
                                         .unservedKind("x", "it's an object"), .mismatchedTypes("x"),
                                         .unsupportedPattern("\"a?\""), .unrepresentableNumber("inf"), .tooManyNodes,
                                         .constantTooLong(2_000)]
        for problem in problems {
            XCTAssertTrue(problem.description.hasSuffix("."), problem.description)
        }
        var indicator = Indicator.defaults[0]
        indicator.predicate = #"target_path == "x""#
        XCTAssertEqual(indicator.sensorProblem, SensorProblem.untyped.description)
        XCTAssertNil(indicator.problem)
    }
}


// MARK: - Programs
extension IndicatorCompilerTests {
    /// A top-level `AND`'s type checks that every event the rule runs on passes are dropped. One inside an `OR` or a
    /// `NOT` stays, as a comparison of the type's number.
    func testOnlyTopLevelTypeChecksAreDropped() throws {
        XCTAssertEqual(try rule(Self.exec + #" AND event.exec.target.executable.name == "curl""#).program.description,
                       #"event.exec.target.executable.name == "curl""#)
        XCTAssertEqual(try rule(Self.exec).program.description, "TRUEPREDICATE")
        let plist = try rule(try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" }).predicate)
        XCTAssertEqual(plist.types, [ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME].map { Int($0.rawValue) }
            .sorted())
        XCTAssertEqual(plist.program.description, #"(((es_event_type == "ES_EVENT_TYPE_NOTIFY_CLOSE" AND "#
                       + #"event.close.modified == 1) OR es_event_type == "ES_EVENT_TYPE_NOTIFY_RENAME") AND "#
                       + #"target_path ENDSWITH[c] ".plist")"#)
        let typeNamedTwice = #"es_event_type IN {"ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_NOTIFY_EXIT"} AND "#
            + Self.exec
        XCTAssertEqual(try rule(typeNamedTwice).program.description, "TRUEPREDICATE")
        let excluded = Self.exec + #" AND NOT es_event_type == "ES_EVENT_TYPE_NOTIFY_EXIT""#
        XCTAssertEqual(try rule(excluded).program.description, #"NOT es_event_type == "ES_EVENT_TYPE_NOTIFY_EXIT""#)
    }

    /// An unmodified close of a `.plist` doesn't match Plist modified, a modified one does, and so does a rename.
    func testUnmodifiedPlistCloseIsntPlistModified() throws {
        let plist = try XCTUnwrap(Indicator.defaults.first { $0.name == "Plist modified" })
        let compiled = CompiledIndicators([plist])
        var values = MessageValueCache()
        for (type, modified, matches) in [("CLOSE", false, false), ("CLOSE", true, true), ("RENAME", false, true)] {
            var message = try corpusMessage("ES_EVENT_TYPE_NOTIFY_" + type)
            message.target_path = "/Users/a/Library/LaunchAgents/com.example.agent.plist"
            if case .close(var close) = message.event {
                close.modified = modified
                message.event = .close(close)
            }
            XCTAssertEqual(compiled.hits(for: message, values: &values).map(\.id), matches ? [plist.id] : [],
                           "\(type) modified: \(modified)")
        }
    }

    /// `AND` in `AND` and `OR` in `OR` are one, and a type check naming an unknown type compares the name.
    func testNestingFlattensAndUnknownTypesCompareNames() throws {
        let source = Self.exec + #" AND ((target_path == "a" AND context == "b") AND (target_path == "c" OR "#
            + #"(context == "d" OR context == "e")))"#
        XCTAssertEqual(try rule(source).program.description, #"(target_path == "a" AND context == "b" AND "#
                       + #"(target_path == "c" OR context == "d" OR context == "e"))"#)
        let unknown = Self.exec + #" AND NOT es_event_type == "ES_EVENT_TYPE_NOTIFY_NOPE""#
        XCTAssertEqual(try rule(unknown).program.nodeCount, 2)
        XCTAssertEqual(try rule(unknown).program.fields, [.esEventType])
    }

    /// A payload test names its event's type, as `es_event_type ==` does: `!= nil` is the type, `== nil` any other,
    /// and an `OR` of them is one check of the types, which a top-level `AND` drops.
    func testPayloadTestsAreTypeChecks() throws {
        let add = Int(ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD.rawValue)
        let alone = try rule("event.btm_launch_item_add != nil")
        XCTAssertEqual(alone.types, [add])
        XCTAssertEqual(alone.program.description, "TRUEPREDICATE")
        let either = try rule(#"(event.create != nil OR event.rename != nil) AND target_path == "a""#)
        XCTAssertEqual(either.types, [ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_RENAME]
            .map { Int($0.rawValue) }.sorted())
        XCTAssertEqual(either.program.description, #"target_path == "a""#)
        let excluded = try rule(Self.exec + " AND (event.fork == nil OR context == \"a\")")
        XCTAssertEqual(excluded.program.description, #"(es_event_type != "ES_EVENT_TYPE_NOTIFY_FORK" OR "#
                       + #"context == "a")"#)
        XCTAssertEqual(problem("event.exec == nil"), .untyped)
        XCTAssertNotNil(problem("event.no_such_event != nil"), "Not a payload")
        let stored = try StreamFilter.Predicate("event.btm_launch_item_add != nil", for: .indicator)
        XCTAssertTrue(StoredEventValues.canEvaluate(stored.parsed))
        XCTAssertEqual(PredicateEventTypes.payloads["event.lw_session_login"], "ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN")
        XCTAssertEqual(PredicateEventTypes.payloads.count, 51)
    }

    /// An `AND`'s or an `OR`'s comparisons of record fields run after its others, at every depth, so a direct field
    /// decides first and the event's encoding is walked only when it has to be. Each keeps its order otherwise.
    func testRecordFieldsAreComparedLast() throws {
        let source = Self.exec + #" AND process.ppid == 1 AND target_path == "a" AND (event.exec.cwd.path == "b" "#
            + #"OR context == "c" OR NOT process.session_id == 2) AND context == "d""#
        XCTAssertEqual(try rule(source).program.description, #"(target_path == "a" AND context == "d" AND "#
                       + #"process.ppid == 1 AND (context == "c" OR event.exec.cwd.path == "b" OR "#
                       + #"NOT process.session_id == 2))"#)
    }

    /// An `AND`'s or an `OR`'s comparisons of `command_line`, `env` and `script_content`, which an event can make
    /// large, run after those of small fields and before those of record fields, at every depth, so a target's path
    /// rules an exec out before its command line is searched. On the same cost, the index anchors the `AND` on the
    /// small field's literal, not the command line's, however the predicate orders them.
    func testLargeFieldsAreComparedAfterSmallOnes() throws {
        let source = Self.exec + #" AND event.exec.command_line CONTAINS "-x" AND process.ppid == 1 AND "#
            + #"(ANY event.exec.env BEGINSWITH "A=" OR event.exec.cwd.path == "b" OR context == "c") AND "#
            + #"event.exec.target.executable.path CONTAINS ".app/" AND NOT event.exec.script_content == "s""#
        let compiled = try rule(source)
        XCTAssertEqual(compiled.program.description, #"(event.exec.target.executable.path CONTAINS ".app/" AND "#
                       + #"event.exec.command_line CONTAINS "-x" AND NOT event.exec.script_content == "s" AND "#
                       + #"process.ppid == 1 AND (context == "c" OR ANY event.exec.env BEGINSWITH "A=" OR "#
                       + #"event.exec.cwd.path == "b"))"#)
        guard case .anyOf(let anchors) = compiled.program.necessity(eventType: compiled.types[0]) else {
            return XCTFail("Not anchored")
        }
        XCTAssertEqual(anchors.map(\.field), [.execTargetExecutablePath])
    }

    /// Each shipped rule's program reads back as a predicate that compiles to the same program, and the same source
    /// compiles to an equal program.
    func testProgramsDescribeThemselves() throws {
        for indicator in Indicator.defaults {
            let compiled = try rule(indicator.predicate)
            let names = compiled.types.map { literal(eventTypeToString(from: es_event_type_t(rawValue: UInt32($0)))) }
            let again = try rule("es_event_type IN {\(names.joined(separator: ", "))} AND \(compiled.program)")
            XCTAssertEqual(again.program, compiled.program, indicator.name)
            XCTAssertEqual(try rule(indicator.predicate), compiled, indicator.name)
        }
        XCTAssertNotEqual(try rule(Self.exec + #" AND context == "a""#).program,
                          try rule(Self.exec + #" AND context == "b""#).program)
    }
}


// MARK: - Helpers
extension IndicatorCompilerTests {
    /// - Parameter source: A predicate.
    /// - Returns: Why it doesn't compile, or `nil`.
    func problem(_ source: String) -> SensorProblem? {
        IndicatorCompiler.problem(with: source)
    }

    /// - Parameter source: A predicate.
    /// - Returns: Its compiled rule.
    /// - Throws: Its problem, when it doesn't compile.
    func rule(_ source: String) throws -> IndicatorCompiler.Rule {
        try IndicatorCompiler.compile(source).get()
    }

    /// - Parameter string: A constant.
    /// - Returns: It quoted, as a predicate writes it.
    func literal(_ string: String) -> String {
        IndicatorValue.literal(string[...])
    }

    /// - Parameter type: An event type's name.
    /// - Returns: The synthetic corpus's first event of that type.
    /// - Throws: The error making the corpus, or a failure when it has none.
    func corpusMessage(_ type: String) throws -> Message {
        try XCTUnwrap(SyntheticCorpus.records().map(\.message).first { $0.es_event_type == type }, type)
    }
}
