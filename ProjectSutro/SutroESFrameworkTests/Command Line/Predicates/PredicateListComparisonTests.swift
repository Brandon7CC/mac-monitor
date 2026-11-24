//
//  PredicateListComparisonTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Comparing a list
/// Pins that a search or a `--predicate` that compares a list as if it were one value is refused as it's typed,
/// with what to write, where it used to be called valid and then fail on every event: `indicators.severity MATCHES
/// "(?i)high"` could check none of them. The editor's tokens leave a comparison's `[c]` out of the key paths.
final class PredicateListComparisonTests: XCTestCase {
    /// A list compared with one value, with no `ANY`, is refused for a search and for `macmonitor`: a list of a
    /// record's own, and a key of the objects in one.
    func testAListComparedAsOneValueIsRefused() {
        let refused = [
            #"indicators.severity MATCHES "(?i)high""#,
            #"indicators.name == "Login""#,
            #"indicators.name != "Login""#,
            #"event.exec.env BEGINSWITH "DYLD_""#,
            #"event.exec.args ENDSWITH ".sh""#,
            #"event.exec.args LIKE "*curl*""#,
            #"indicators.severity > "a""#,
            #"event.exec != nil AND (process.pid > 1 OR NOT indicators.name ==[c] "login")"#,
        ]
        for audience in [PredicateAudience.search, .commandLine] {
            for predicate in refused {
                XCTAssertThrowsError(try StreamFilter.Predicate.parse(predicate, for: audience), predicate)
            }
        }
        XCTAssertThrowsError(try StreamFilter.Predicate.parse(refused[0], for: .search)) { error in
            XCTAssertEqual((error as? CommandLineUsageError)?.message, """
                The predicate can't use 'indicators.severity MATCHES "(?i)high"': indicators.severity is a list. \
                Compare each of its values with ANY, as in ANY indicators.severity MATCHES "(?i)high", or test the \
                whole list with CONTAINS.
                """)
        }
    }

    /// Every way a list is compared is still taken: each value with `ANY`, `ALL` or `NONE`, the whole list with
    /// `CONTAINS`, `IN`, a set or `nil`, and its size.
    func testEveryOtherComparisonOfAListIsTaken() {
        let taken = [
            #"ANY indicators.severity MATCHES "(?i)high""#,
            #"ANY indicators.name ==[c] "login""#,
            #"NONE indicators.name == "Login""#,
            #"ALL event.exec.args != """#,
            #"indicators.severity CONTAINS "high""#,
            #""high" IN indicators.severity"#,
            #"event.exec.env == nil"#,
            #"event.exec.env != nil"#,
            #"event.exec.env.@count > 1"#,
            #"event.exec.args == {"a", "b"}"#,
            #"process.executable.path MATCHES ".*curl""#,
        ]
        for audience in [PredicateAudience.search, .commandLine] {
            for predicate in taken {
                XCTAssertNoThrow(try StreamFilter.Predicate.parse(predicate, for: audience), predicate)
            }
        }
    }

    /// What the refusal says to write finds the events: each value compared with `ANY`.
    func testWhatItSaysToWriteMatches() throws {
        let record: NSDictionary = ["indicators": [["name": "Login", "severity": "low"],
                                                   ["name": "XProtect detection", "severity": "High"]]]
        let any = try StreamFilter.Predicate(#"ANY indicators.severity MATCHES "(?i)high""#, for: .search)
        XCTAssertTrue(try any.evaluate(on: record))
        let none = try StreamFilter.Predicate(#"ANY indicators.severity MATCHES "(?i)medium""#, for: .search)
        XCTAssertFalse(try none.evaluate(on: record))
    }

    /// A comparison's options, as in `==[c]`, are part of the comparison: the `c` is no key path, so the editor
    /// doesn't underline it.
    func testAComparisonsOptionsAreNoKeyPath() {
        for source in [#"ANY indicators.name ==[c] "login""#, #"process.executable.name !=[cd] "curl""#,
                       #"target_path BEGINSWITH[c] "/tmp""#] {
            let tokens = PredicateText.tokens(in: source)
            XCTAssertEqual(tokens.filter { $0.kind == .keyPath }.count, 1, source)
            XCTAssertTrue(tokens.contains { ($0.kind == .comparison || $0.kind == .keyword) && $0.text.hasSuffix("]") },
                          source)
        }
    }
}
