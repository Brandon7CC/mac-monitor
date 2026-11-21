//
//  PredicateAudienceKeyPathTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Which key paths an editor underlines and completes
/// Pins that the predicate editor underlines a key path only where the predicate is refused for it, and completes
/// the key paths it may use. The editor asks ``PredicateAudience/validKeyCount(of:)``, and the parser decides
/// what's refused, so the two are checked against each other: an indicator's editor once underlined
/// `lineage.paths`, which the Security Extension reads.
final class PredicateAudienceKeyPathTests: XCTestCase {
    /// - Parameter path: A key path.
    /// - Returns: Its keys.
    private func keys(_ path: String) -> [String] {
        path.split(separator: ".").map(String.init)
    }

    /// - Parameter predicate: A predicate.
    /// - Returns: The key paths it names, as the editor's highlighter finds them.
    private func keyPaths(in predicate: String) -> [String] {
        PredicateText.tokens(in: predicate).filter { $0.kind == .keyPath }
            .map { PredicateText.keys(of: $0).joined(separator: ".") }
    }

    /// Every field an indicator reads directly is valid in an indicator's editor, the ancestors' among them.
    func testEveryFieldAnIndicatorReadsIsValidInItsEditor() {
        XCTAssertFalse(LineageField.all.isEmpty)
        for field in IndicatorField.allCases {
            XCTAssertEqual(PredicateAudience.indicator.validKeyCount(of: keys(field.path)), keys(field.path).count,
                           field.path)
        }
    }

    /// An ancestor's field is valid where the parser accepts it, in an indicator, and underlined from its first
    /// key where the parser refuses it: the window's search and `macmonitor stream --predicate`, whose records
    /// don't have it.
    func testAnAncestorsFieldIsValidOnlyWhereItIsRead() {
        for field in LineageField.all {
            let predicate = field.kind == .strings ? #"ANY \#(field.path) == "x""# : #"\#(field.path) == "x""#
            XCTAssertNoThrow(try StreamFilter.Predicate.parse(predicate, for: .indicator), predicate)
            XCTAssertEqual(PredicateAudience.indicator.validKeyCount(of: keys(field.path)), keys(field.path).count,
                           field.path)
            for audience in [PredicateAudience.search, .commandLine] {
                XCTAssertThrowsError(try StreamFilter.Predicate.parse(predicate, for: audience), predicate)
                XCTAssertEqual(audience.validKeyCount(of: keys(field.path)), 0, field.path)
            }
        }
    }

    /// While it's being typed, an ancestor's field is valid as far as it starts one, and underlined from the first
    /// key that doesn't. A record's key path is checked against the record, as before.
    func testAKeyPathIsValidAsFarAsItLeadsSomewhere() {
        let valid = { PredicateAudience.indicator.validKeyCount(of: self.keys($0)) }
        XCTAssertEqual(valid("lineage"), 1)
        XCTAssertEqual(valid("lineage.parent"), 2)
        XCTAssertEqual(valid("launched_by.origin.executable"), 3)
        XCTAssertEqual(valid("lineage.nope"), 1)
        XCTAssertEqual(valid("lineage.parent.nope"), 2)
        XCTAssertEqual(valid("lineage.paths.nope"), 2)
        XCTAssertEqual(valid("event.exec.target.executable.path"), 5)
        XCTAssertEqual(valid("event.exec.nope"), 2)
        XCTAssertEqual(valid("nope.exec"), 0)
        for audience in [PredicateAudience.indicator, .search, .commandLine] {
            XCTAssertEqual(audience.validKeyCount(of: keys("event.exec.nope")), 2)
            XCTAssertEqual(audience.validKeyCount(of: keys("process.audit_token.pid")), 3)
        }
    }

    /// - Parameters:
    ///   - text: A predicate, with the cursor at its end.
    ///   - audience: What it's for.
    /// - Returns: The words that complete its last word.
    private func completions(_ text: String, for audience: PredicateAudience = .indicator) -> [String] {
        PredicateText.completions(in: text, at: (text as NSString).length, for: audience)?.words ?? []
    }

    /// An indicator's editor completes an ancestor's field key by key, as it completes a record's. The window's
    /// search and `macmonitor` offer none, as they refuse them.
    func testAnIndicatorsEditorCompletesAncestorsFields() {
        XCTAssertEqual(completions("lin").first, "lineage")
        XCTAssertEqual(completions("laun").first, "launched_by")
        XCTAssertEqual(completions("li"), ["lineage", "LIKE"])
        XCTAssertEqual(completions("lineage."), [
            "lineage.parent", "lineage.grandparent", "lineage.origin", "lineage.paths", "lineage.command_lines",
            "lineage.signing_ids", "lineage.team_ids", "lineage.codesigning_types",
        ])
        XCTAssertEqual(completions("event.exec != nil AND ANY launched_by.pa"),
                       ["launched_by.parent", "launched_by.paths"])
        XCTAssertEqual(completions("lineage.origin."), [
            "lineage.origin.executable", "lineage.origin.command_line", "lineage.origin.signing_id",
            "lineage.origin.team_id", "lineage.origin.codesigning_type",
        ])
        XCTAssertEqual(completions("lineage.origin.executable."), ["lineage.origin.executable.path"])
        XCTAssertEqual(completions("lineage.paths."), [])
        XCTAssertEqual(completions("lineage.nope."), [])
        XCTAssertTrue(completions("signing_ids").contains("lineage.signing_ids"), "By its last key")
        XCTAssertTrue(completions("exec").contains("event.exec"), "A record's keys are completed as before")
        for audience in [PredicateAudience.search, .commandLine] {
            XCTAssertFalse(completions("lin", for: audience).contains("lineage"))
            XCTAssertEqual(completions("li", for: audience), ["LIKE"])
            XCTAssertEqual(completions("lineage.", for: audience), [])
            XCTAssertFalse(completions("signing_ids", for: audience).contains("lineage.signing_ids"))
        }
        XCTAssertEqual(PredicateText.completions(in: "li", at: 2)?.words, ["LIKE"], "The search unless told otherwise")
    }

    /// Every completion offered under an ancestor's key is valid where it's offered, and following them reaches
    /// every ancestor's field and nothing else. Each says what it is.
    func testEveryCompletionOfAnAncestorsFieldIsValid() throws {
        var reached: Set<String> = [], open = ["lineage", "launched_by"]
        while let path = open.popLast() {
            XCTAssertEqual(PredicateAudience.indicator.validKeyCount(of: keys(path)), keys(path).count, path)
            let next = completions(path + ".")
            if next.isEmpty { reached.insert(path) }
            open += next
        }
        XCTAssertEqual(reached, Set(LineageField.all.map(\.path)))
        let items = try XCTUnwrap(PredicateText.completions(in: "lineage.", at: 8, for: .indicator)).items
        XCTAssertEqual(items.map(\.kind), Array(repeating: .key, count: items.count))
        XCTAssertEqual(items.map(\.type), ["object", "object", "object", "array", "array", "array", "array", "array"])
        XCTAssertTrue(items.allSatisfy { $0.summary?.isEmpty == false })
        let leaf = try XCTUnwrap(PredicateText.completions(in: "lineage.parent.sign", at: 19, for: .indicator)).items
        XCTAssertEqual(leaf.map(\.type), ["string"])
        let top = try XCTUnwrap(PredicateText.completions(in: "li", at: 2, for: .indicator)).items.first
        XCTAssertEqual(top?.type, "object")
        XCTAssertEqual(top?.summary?.isEmpty, false)
    }

    /// No predicate Mac Monitor's own indicators have, or the indicators repository's lineage indicator, is
    /// underlined anywhere in an indicator's editor.
    func testNoShippedPredicateIsUnderlined() {
        var predicates = [
            #"event.exec != nil AND event.exec.target.executable.path ENDSWITH "/osascript" "#
                + #"AND ANY lineage.paths ENDSWITH "/curl""#,
            #"event.exec != nil AND launched_by.parent.signing_id == "com.apple.Safari""#,
        ]
        for indicator in Indicator.defaults {
            switch indicator.rule {
            case .event(let predicate): predicates.append(predicate)
            case .sequence(let sequence): predicates += sequence.steps.map(\.predicate)
            }
        }
        XCTAssertGreaterThan(predicates.count, 40)
        for predicate in predicates {
            XCTAssertNoThrow(try StreamFilter.Predicate.parse(predicate, for: .indicator), predicate)
            for path in keyPaths(in: predicate) {
                XCTAssertEqual(PredicateAudience.indicator.validKeyCount(of: keys(path)), keys(path).count,
                               "\(path) in \(predicate)")
            }
        }
    }
}
