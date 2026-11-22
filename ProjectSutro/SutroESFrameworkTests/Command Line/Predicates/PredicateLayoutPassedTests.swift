//
//  PredicateLayoutPassedTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/22/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - The lines an event passed
/// Pins which lines of a laid-out predicate Event Facts' Indicators popover marks as passed
/// (``PredicateLayout/passedLines(by:eventType:isWholeRule:)``): every condition a matched rule's `AND`s make certain,
/// and otherwise those whose condition holds on what a hit says the event had, never one that only rules something
/// out.
final class PredicateLayoutPassedTests: XCTestCase {
    private static let exec = "ES_EVENT_TYPE_NOTIFY_EXEC"
    private static let name = "event.exec.target.executable.name"
    private static let path = "event.exec.target.executable.path"

    /// - Parameters:
    ///   - predicate: A predicate.
    ///   - matched: What a hit lists, as key paths and values, in order.
    ///   - eventType: The event's type, or `nil`.
    ///   - whole: Is the predicate the whole rule the event matched? A sequence's step isn't, and each of its lines
    ///     is checked on what's listed.
    /// - Returns: The text of the lines the event passed, in order.
    private func passed(_ predicate: String, _ matched: KeyValuePairs<String, IndicatorMatchedField.Value>,
                        eventType: String? = nil, whole: Bool = false) -> [String] {
        let layout = PredicateLayout(predicate)
        let fields = matched.map { IndicatorMatchedField(field: $0.key, value: $0.value) }
        return layout.passedLines(by: fields, eventType: eventType, isWholeRule: whole).map { layout.lines[$0].text }
    }

    // MARK: A matched rule

    /// Every condition a matched rule joins with `AND` held, or it wouldn't have matched: each is passed, a `!=` a
    /// value and a `NOT` too, and one that reads nothing the hit lists.
    func testEveryConditionAMatchedRuleJoinsWithANDIsPassed() {
        let rule = "event.exec != nil AND event.exec.target.euid == 0 AND event.exec.target.ruid != 0 "
            + #"AND NOT \#(Self.name) == "login" AND process.signing_id == nil"#
        XCTAssertEqual(passed(rule, ["event.exec.target.euid": .integer(0)], whole: true), [
            "event.exec != nil",
            "AND event.exec.target.euid == 0",
            "AND event.exec.target.ruid != 0",
            #"AND NOT \#(Self.name) == "login""#,
            "AND process.signing_id == nil",
        ])
        XCTAssertEqual(passed(rule, ["event.exec.target.euid": .integer(0)]), ["AND event.exec.target.euid == 0"],
                       "A sequence's step may be one another event passed")
    }

    /// In a matched rule, a group joined with `AND` held too: every line of one whose own conditions are joined
    /// with `AND` is passed, and a group under `NOT` has the lines that open and close it passed, not what it rules
    /// out. An `OR`'s alternatives are checked on what's listed, as one of them held, not each.
    func testAMatchedRulesGroupsArePassedByWhatTheyJoin() {
        let rule = #"\#(Self.name) == "curl" AND (\#(Self.path) BEGINSWITH "/usr" OR \#(Self.path) != "/bin/curl") "#
            + #"AND NOT (\#(Self.path) BEGINSWITH "/opt" OR \#(Self.name) == "wget") "#
            + "AND (process.is_platform_binary == NO AND process.audit_token.pid != 1)"
        let matched: KeyValuePairs<String, IndicatorMatchedField.Value> = [
            Self.name: .string("curl"), Self.path: .string("/usr/bin/curl"),
        ]
        XCTAssertEqual(passed(rule, matched, whole: true), [
            #"\#(Self.name) == "curl""#,
            #"\#(Self.path) BEGINSWITH "/usr""#,
            "AND NOT (",
            ")",
            "process.is_platform_binary == NO",
            "AND process.audit_token.pid != 1",
        ])
    }

    /// A matched rule whose conditions are joined with `OR` says only that one held: each is checked on what's
    /// listed, and one that only rules something out isn't passed.
    func testAMatchedRulesORIsCheckedOnWhatsListed() {
        let rule = #"\#(Self.name) != "wget" OR \#(Self.path) ENDSWITH "/curl" OR \#(Self.path) ENDSWITH "/nc""#
        XCTAssertEqual(passed(rule, [Self.path: .string("/usr/bin/curl")], whole: true),
                       [#"OR \#(Self.path) ENDSWITH "/curl""#])
    }

    // MARK: What's listed

    /// Of an `OR`'s alternatives on one key path, only the one that holds for the event's value is passed, and the
    /// lines that open and close the group never are.
    func testOnlyTheAlternativeThatHoldsIsPassed() {
        let rule = #"(\#(Self.path) CONTAINS "/LaunchAgents/" OR \#(Self.path) CONTAINS "/LaunchDaemons/") "#
            + #"AND \#(Self.path) ENDSWITH ".plist""#
        XCTAssertEqual(passed(rule, [Self.path: .string("/Library/LaunchAgents/a.plist")]), [
            #"\#(Self.path) CONTAINS "/LaunchAgents/""#,
            #"AND \#(Self.path) ENDSWITH ".plist""#,
        ])
    }

    /// A line that reads nothing the hit lists isn't passed, whatever it says.
    func testALineThatReadsNothingListedIsNotPassed() {
        let rule = #"\#(Self.name) == "curl" AND process.signing_id == nil AND process.team_id == "A""#
        XCTAssertEqual(passed(rule, [Self.name: .string("curl")]), [#"\#(Self.name) == "curl""#])
        XCTAssertEqual(passed(rule, [:]), [])
    }

    /// What only rules something out is never passed: a `NOT`, a `!=` a value, `NONE`, and every line of a group
    /// under `NOT`. A `!= nil` says the event has a value, and is.
    func testWhatOnlyRulesOutIsNeverPassed() {
        let rule = #"\#(Self.name) != "wget" AND NOT \#(Self.name) == "wget" AND \#(Self.name) != nil "#
            + #"AND NOT (\#(Self.name) == "curl" AND \#(Self.path) BEGINSWITH "/opt") "#
            + #"AND NONE event.exec.args == "curl" AND \#(Self.path) BEGINSWITH "/usr""#
        let matched: KeyValuePairs<String, IndicatorMatchedField.Value> = [
            Self.name: .string("curl"), Self.path: .string("/usr/bin/curl"), "event.exec.args": .string("curl"),
        ]
        XCTAssertEqual(passed(rule, matched), [
            "AND \(Self.name) != nil",
            #"AND \#(Self.path) BEGINSWITH "/usr""#,
        ])
    }

    /// A line that names the event's type is passed when the type is known: its payload's `!= nil`, and
    /// `es_event_type`. Another type's isn't.
    func testTheEventsTypeIsPassed() {
        let rule = #"event.exec != nil AND es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" "#
            + #"AND (event.fork != nil OR es_event_type IN {"ES_EVENT_TYPE_NOTIFY_FORK", "ES_EVENT_TYPE_NOTIFY_EXEC"})"#
        XCTAssertEqual(passed(rule, [:], eventType: Self.exec), [
            "event.exec != nil",
            #"AND es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC""#,
            #"OR es_event_type IN {"ES_EVENT_TYPE_NOTIFY_FORK", "ES_EVENT_TYPE_NOTIFY_EXEC"}"#,
        ])
        XCTAssertEqual(passed(rule, [:]), [])
        XCTAssertEqual(passed("event.exec != nil AND \(Self.name) != nil", [Self.name: .string("curl")]),
                       ["AND \(Self.name) != nil"])
    }

    /// `ANY` is checked on the strings the hit lists for its array, however many, in a group that stays on its line.
    func testANYIsCheckedOnTheStringsListed() {
        let rule = #"(ANY event.exec.env BEGINSWITH "DYLD_") AND ANY event.exec.env ENDSWITH[c] ".DYLIB" "#
            + #"AND ANY event.exec.args == "-o""#
        XCTAssertEqual(passed(rule, ["event.exec.env": .string("DYLD_INSERT_LIBRARIES=/tmp/x.dylib")]), [
            #"(ANY event.exec.env BEGINSWITH "DYLD_")"#,
            #"AND ANY event.exec.env ENDSWITH[c] ".DYLIB""#,
        ])
        XCTAssertEqual(passed(#"\#(Self.name) == "ls" AND (ANY event.exec.env BEGINSWITH "DYLD_")"#,
                              ["event.exec.env": .string("DYLD_A=1")]),
                       [#"AND (ANY event.exec.env BEGINSWITH "DYLD_")"#])
        XCTAssertEqual(passed(rule, ["event.exec.env": .string("HOME=/a"), "event.exec.env": .string("DYLD_A=1"),
                                     "event.exec.args": .string("-o")]), [
            #"(ANY event.exec.env BEGINSWITH "DYLD_")"#,
            #"AND ANY event.exec.args == "-o""#,
        ])
    }

    /// Numbers and Booleans are compared as a record writes them, and a Boolean key path may stand alone.
    func testNumbersAndBooleansAreCompared() {
        let rule = "process.audit_token.pid > 100 AND process.audit_token.pid < 50 "
            + "AND process.is_platform_binary == NO AND event.exec.target.is_adhoc_signed"
        let matched: KeyValuePairs<String, IndicatorMatchedField.Value> = [
            "process.audit_token.pid": .integer(321), "process.is_platform_binary": .boolean(false),
            "event.exec.target.is_adhoc_signed": .boolean(true),
        ]
        XCTAssertEqual(passed(rule, matched), [
            "process.audit_token.pid > 100",
            "AND process.is_platform_binary == NO",
            "AND event.exec.target.is_adhoc_signed",
        ])
    }

    /// A value the hit may have cut short can't be checked past its end, so each line that reads it is passed. A
    /// shorter value is checked.
    func testALineThatReadsACutValueIsPassed() {
        let rule = #"event.exec.command_line ENDSWITH " --now" OR event.exec.command_line BEGINSWITH "wget ""#
        let long = IndicatorMatchedField.Value.string("curl " + String(repeating: "a", count: 251))
        XCTAssertTrue(long.isCut)
        XCTAssertEqual(passed(rule, ["event.exec.command_line": long]).count, 2)
        let short = IndicatorMatchedField.Value.string("curl a --now")
        XCTAssertFalse(short.isCut)
        XCTAssertEqual(passed(rule, ["event.exec.command_line": short]),
                       [#"event.exec.command_line ENDSWITH " --now""#])
    }

    /// A condition that can't be evaluated on what's listed, such as `MATCHES` on a number, isn't passed.
    func testAConditionThatCantBeEvaluatedIsNotPassed() {
        XCTAssertEqual(passed(#"process.audit_token.pid MATCHES "3.*" OR process.audit_token.pid == 321"#,
                              ["process.audit_token.pid": .integer(321)]),
                       ["OR process.audit_token.pid == 321"])
    }

    /// What the Security Extension lists for a hit marks the lines its rule passed: every condition it joins with
    /// `AND`, and the alternative that matched.
    func testAHitsOwnListMarksItsRule() throws {
        var message = try corpusExec { exec in
            exec.target.executable?.path = "/usr/bin/curl"
            exec.env = ["HOME=/Users/a", "DYLD_INSERT_LIBRARIES=/tmp/x.dylib"]
        }
        message.process.is_platform_binary = false
        let rule = #"event.exec != nil AND (\#(Self.name) == "wget" OR \#(Self.path) ENDSWITH "/curl") "#
            + #"AND (ANY event.exec.env BEGINSWITH "DYLD_INSERT_LIBRARIES=") "#
            + #"AND process.is_platform_binary == NO AND NOT (\#(Self.path) BEGINSWITH "/opt/")"#
        let compiled = CompiledIndicators([ownIndicator("Mine", rule)])
        XCTAssertEqual(compiled.problems.map(\.reason), [])
        var values = MessageValueCache()
        let hit = try XCTUnwrap(compiled.hits(for: message, values: &values).first)
        let layout = PredicateLayout(rule)
        let marked = layout.passedLines(by: try XCTUnwrap(hit.matched), eventType: Self.exec)
        XCTAssertEqual(marked.map { layout.lines[$0].text }, [
            "event.exec != nil",
            #"OR \#(Self.path) ENDSWITH "/curl""#,
            #"AND (ANY event.exec.env BEGINSWITH "DYLD_INSERT_LIBRARIES=")"#,
            "AND process.is_platform_binary == NO",
            #"AND NOT (\#(Self.path) BEGINSWITH "/opt/")"#,
        ])
    }

    /// Every shipped predicate's lines can be checked, as a matched rule and as a step, whatever the event's type.
    /// With nothing listed, a step's lines that name the type are the only ones passed.
    func testShippedPredicatesAreChecked() {
        for indicator in Indicator.eventDefaults {
            let predicate = indicator.predicate!
            let layout = PredicateLayout(predicate)
            XCTAssertEqual(layout.passedLines(by: [], isWholeRule: false), [], indicator.name)
            _ = layout.passedLines(by: [], eventType: Self.exec)
            for line in layout.passedLines(by: [], eventType: Self.exec, isWholeRule: false) {
                let text = layout.lines[line].text
                XCTAssertTrue(text.contains("es_event_type") || text.contains("event.exec"),
                              "\(indicator.name): \(text)")
            }
        }
    }
}
