//
//  PredicateLayoutTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Predicate layout
/// Pins how Event Facts' Indicators popover lays out a predicate to read (``PredicateLayout``): a condition a line,
/// groups with an `AND` or `OR` indented a level deeper, everything else left on its line, and the lines joined back
/// to the stored predicate exactly, as Copy puts it on the pasteboard. Also pins the tokens the popover colors for
/// every operator and modifier the shipped indicators use.
final class PredicateLayoutTests: XCTestCase {
    /// The comparisons and keywords, with their modifiers, the shipped indicators' predicates use. One a shipped
    /// indicator starts using must be added here, once its tokens are checked.
    private static let shippedOperators: [PredicateText.Token.Kind: Set<String>] = [
        .comparison: ["==", "!=", "<", ">="],
        .keyword: ["AND", "OR", "NOT", "ANY", "IN", "BEGINSWITH", "BEGINSWITH[c]", "CONTAINS", "CONTAINS[c]",
                   "ENDSWITH", "ENDSWITH[c]", "LIKE", "LIKE[c]", "YES", "nil"],
    ]

    /// - Parameter layout: A layout.
    /// - Returns: Its lines as depth and text, to compare.
    private func lines(_ layout: PredicateLayout) -> [String] {
        layout.lines.map { "\($0.depth) \($0.text)" }
    }

    /// Every shipped indicator's predicate is on one line, its lines join back to it exactly, and its laid-out text,
    /// pasted back and put on one line, is it again. Laying out the laid-out text gives the same layout.
    func testShippedPredicatesRoundTrip() {
        XCTAssertEqual(Indicator.defaults.count, 43)
        for indicator in Indicator.defaults {
            let predicate = indicator.predicate
            let layout = PredicateLayout(predicate)
            XCTAssertEqual(PredicateLayout.oneLine(predicate), predicate, indicator.name)
            XCTAssertEqual(layout.oneLine, predicate, indicator.name)
            XCTAssertEqual(PredicateLayout.oneLine(layout.text), predicate, indicator.name)
            XCTAssertEqual(PredicateLayout(layout.text), layout, indicator.name)
            XCTAssertFalse(layout.lines.contains { $0.text.isEmpty || $0.text.first?.isWhitespace == true },
                           indicator.name)
        }
    }

    /// Dylib inserted, the deepest shipped predicate, lays out as the owner's approved design shows it.
    func testShippedDylibInsertedLayout() throws {
        let indicator = try XCTUnwrap(Indicator.defaults.first { $0.name == "Dylib inserted" })
        let env = "ANY event.exec.env"
        let xcode = "/Applications/Xcode*.app/Contents/Developer/*"
        let nested = "/Applications/Xcode*/*.app/Contents/Developer/*"
        XCTAssertEqual(PredicateLayout(indicator.predicate).text, [
            "event.exec != nil",
            "  AND (",
            #"    (\#(env) BEGINSWITH "DYLD_INSERT_LIBRARIES=")"#,
            "    OR (",
            "      (",
            #"        event.exec.target.executable.name == "launchctl""#,
            #"        OR event.exec.target.signing_id == "com.apple.xpc.launchctl""#,
            "      )",
            #"      AND event.exec.command_line CONTAINS " setenv ""#,
            #"      AND event.exec.command_line CONTAINS "DYLD_INSERT_LIBRARIES""#,
            "    )",
            "  )",
            "  AND NOT (",
            "    (",
            #"      event.exec.target.executable.path CONTAINS "/Build/Products/""#,
            #"      OR event.exec.target.executable.path BEGINSWITH "/Applications/Xcode""#,
            "    )",
            #"    AND NOT \#(env) LIKE "DYLD_INSERT_LIBRARIES=*/../*""#,
            "    AND (",
            "      (",
            #"        \#(env) LIKE "DYLD_INSERT_LIBRARIES=\#(xcode)""#,
            #"        AND NOT \#(env) LIKE "DYLD_INSERT_LIBRARIES=*:*""#,
            #"        AND NOT \#(env) LIKE "DYLD_INSERT_LIBRARIES=\#(nested)""#,
            "      )",
            "      OR (",
            #"        \#(env) LIKE "DYLD_INSERT_LIBRARIES=\#(xcode):\#(xcode)""#,
            #"        AND NOT \#(env) LIKE "DYLD_INSERT_LIBRARIES=*:*:*""#,
            #"        AND NOT \#(env) LIKE "DYLD_INSERT_LIBRARIES=\#(nested):*""#,
            #"        AND NOT \#(env) LIKE "DYLD_INSERT_LIBRARIES=*:\#(nested)""#,
            "      )",
            #"      OR \#(env) == "DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib""#,
            "    )",
            "  )",
        ].joined(separator: "\n"))
    }

    /// Nested groups each go a level deeper and close back at the level they opened at. A group with no `AND` or
    /// `OR`, a `NOT (...)` of one condition, a quoted string's parentheses and `AND`, and a `SUBQUERY`'s arguments stay
    /// on their line; `NOT(` with no space is still a group. `AND(` with no space, `&&` and `||` join as `AND` and
    /// `OR` do, and `SUBQUERY (` with a space is still a function's arguments.
    func testNestedGroupsIndent() {
        let predicate = #"a == 1 AND ((b == 2) OR (NOT(c == 3 OR d == 4) AND e CONTAINS "x (y) AND z")) "#
            + "AND NOT (f == 5) AND SUBQUERY(correlated, $e, $e.g == 1 AND $e.h == 2).@count > 0"
        let layout = PredicateLayout(predicate)
        XCTAssertEqual(lines(layout), [
            "0 a == 1",
            "1 AND (",
            "2 (b == 2)",
            "2 OR (",
            "3 NOT(",
            "4 c == 3",
            "4 OR d == 4",
            "3 )",
            #"3 AND e CONTAINS "x (y) AND z""#,
            "2 )",
            "1 )",
            "1 AND NOT (f == 5)",
            "1 AND SUBQUERY(correlated, $e, $e.g == 1 AND $e.h == 2).@count > 0",
        ])
        XCTAssertEqual(layout.lines.map(\.joint), ["", " ", "", " ", "", "", " ", "", " ", "", "", " ", " "])
        XCTAssertEqual(layout.oneLine, predicate)
        XCTAssertEqual(PredicateLayout.oneLine(layout.text), predicate)

        let written: [(predicate: String, lines: [String])] = [
            ("a == 1 AND(b == 2 OR c == 3)", ["0 a == 1", "1 AND(", "2 b == 2", "2 OR c == 3", "1 )"]),
            ("a == 1 && (b == 2 || c == 3)", ["0 a == 1", "1 && (", "2 b == 2", "2 || c == 3", "1 )"]),
            ("SUBQUERY (correlated, $e, $e.g == 1 AND $e.h == 2).@count > 0 AND x == 1",
             ["0 SUBQUERY (correlated, $e, $e.g == 1 AND $e.h == 2).@count > 0", "1 AND x == 1"]),
        ]
        for (predicate, expected) in written {
            let layout = PredicateLayout(predicate)
            XCTAssertEqual(lines(layout), expected, predicate)
            XCTAssertEqual(layout.oneLine, predicate)
        }
    }

    /// A predicate that starts with a group opens it on the first line, and its `AND` after the group is indented
    /// under it. A group that isn't closed holds the rest, and a `)` with no `(` stays on its line.
    func testGroupsAtTheEdges() {
        XCTAssertEqual(lines(PredicateLayout("(a == 1 OR b == 2) AND c == 3")),
                       ["0 (", "1 a == 1", "1 OR b == 2", "0 )", "1 AND c == 3"])
        XCTAssertEqual(lines(PredicateLayout("a == 1 AND (b == 2 OR c == 3")),
                       ["0 a == 1", "1 AND (", "2 b == 2", "2 OR c == 3"])
        XCTAssertEqual(lines(PredicateLayout("a == 1) OR b == 2")), ["0 a == 1)", "1 OR b == 2"])
        XCTAssertEqual(lines(PredicateLayout("a == 1")), ["0 a == 1"])
        XCTAssertEqual(PredicateLayout("  ").lines, [])
        XCTAssertEqual(PredicateLayout("").text, "")
    }

    /// Putting a predicate on one line changes only whitespace that breaks a line, outside quoted strings: a space
    /// between words, nothing after `(` or before `)`. Whitespace on one line and inside strings is kept as it is.
    func testOneLine() {
        XCTAssertEqual(PredicateLayout.oneLine("a  ==  1"), "a  ==  1")
        XCTAssertEqual(PredicateLayout.oneLine("( a == 1 )"), "( a == 1 )")
        XCTAssertEqual(PredicateLayout.oneLine("\n  a == 1\n  AND (\n    b == 2\n  )\n"), "a == 1 AND (b == 2)")
        XCTAssertEqual(PredicateLayout.oneLine("p CONTAINS \"one\n  two\" AND\r\nq == 'it\\'s\n x'"),
                       "p CONTAINS \"one\n  two\" AND q == 'it\\'s\n x'")
        XCTAssertEqual(PredicateLayout.oneLine(#"p == "\"(" AND"# + "\n" + #"q == ")""#), #"p == "\"(" AND q == ")""#)
    }

    /// The operators and modifiers the shipped indicators use are exactly those pinned, each read as one token of
    /// its kind, so the popover colors it as one; `nil`, `YES` and `NO` are keywords. Laying a predicate out never
    /// splits, merges or recolors a token, and no token runs over a line.
    func testShippedOperatorTokens() {
        var used: [PredicateText.Token.Kind: Set<String>] = [:]
        for indicator in Indicator.defaults {
            let tokens = PredicateText.tokens(in: indicator.predicate)
            for token in tokens where [.comparison, .keyword].contains(token.kind) {
                used[token.kind, default: []].insert(token.text)
            }
            let text = PredicateLayout(indicator.predicate).text
            let laidOut = PredicateText.tokens(in: text)
            XCTAssertEqual(laidOut.map(\.kind), tokens.map(\.kind), indicator.name)
            XCTAssertEqual(laidOut.map(\.text), tokens.map(\.text), indicator.name)
            XCTAssertFalse(laidOut.contains { $0.text.contains("\n") }, indicator.name)
        }
        XCTAssertEqual(used, Self.shippedOperators)
        for (kind, spellings) in Self.shippedOperators {
            for spelling in spellings {
                let tokens = PredicateText.tokens(in: "a \(spelling) b")
                XCTAssertEqual(tokens.map(\.text), ["a", spelling, "b"], spelling)
                XCTAssertEqual(tokens.dropFirst().first?.kind, kind, spelling)
            }
        }
        for constant in ["nil", "YES", "NO"] {
            XCTAssertEqual(PredicateText.tokens(in: "a == \(constant)").last?.kind, .keyword, constant)
        }
    }
}

