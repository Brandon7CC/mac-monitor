//
//  StringMatchingTests+Fields.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Fields compared with fields
/// Pins a field compared with another field of the same event to `NSPredicate`'s comparison of the two values: each
/// operator by `[]`, `[c]`, `[d]` and `[cd]` on every pair of ASCII, NFC and NFD strings, the Kelvin sign, the long s,
/// CR LF and empty strings, the nil table on either side and both, Booleans, whole numbers and fractions ordered as
/// numbers, and values past Foundation's window.
extension StringMatchingTests {
    /// The two string fields the tests compare, each of which can be missing.
    static let leftField = "event.exec.script_content", rightField = "event.exec.target.team_id"
    /// Each side's values: the values, and pieces that start, end or equal them.
    static let sides = values + ["re", "RE", "Re", "e\u{301}", "\u{E9}", "K", "k", "\u{212A}", "sume", ".PLIST",
                                 "plist", "\nb", "a\r", "Re\u{301}sume"]

    /// `==`, `!=`, `BEGINSWITH` and `ENDSWITH` of two fields, by every set of options, on every pair of values.
    func testFieldComparisonsAreNSPredicates() throws {
        var compared = 0
        for op in ["==", "!=", "BEGINSWITH", "ENDSWITH"] {
            for options in Self.options {
                let comparison = op + options
                let program = try compile("\(Self.leftField) \(comparison) \(Self.rightField)")
                let predicate = NSPredicate(format: "a \(comparison) b")
                for left in Self.sides {
                    for right in Self.sides {
                        let expected = predicate.evaluate(with: ["a": left, "b": right])
                        XCTAssertEqual(evaluate(program, on: try pair(left, right)), expected,
                                       "\(escaped(left)) \(comparison) \(escaped(right))")
                        compared += 1
                    }
                }
            }
        }
        XCTAssertGreaterThan(compared, 15_000)
    }

    /// A missing value, `nil` or `NSNull`, on either side or both, is compared as `NSPredicate` compares it: two are
    /// equal, so `==`, `<=` and `>=` are true on them, and one differs from every present value, so only `!=` is
    /// true. `BEGINSWITH` and `ENDSWITH` are false on any. `NOT` turns each around.
    func testTheFieldNilTable() throws {
        let missing: [Any?] = [nil, NSNull()]
        let strings: [String?] = [nil, "", "x"]
        for comparison in ["==", "!=", "BEGINSWITH", "ENDSWITH", "==[c]", "!=[cd]", "BEGINSWITH[d]", "ENDSWITH[c]"] {
            let program = try compile("\(Self.leftField) \(comparison) \(Self.rightField)")
            let notProgram = try compile("NOT \(Self.leftField) \(comparison) \(Self.rightField)")
            for left in strings {
                for right in strings where left == nil || right == nil {
                    for spelling in missing {
                        let expected = NSPredicate(format: "a \(comparison) b")
                            .evaluate(with: record(["a": left.map { $0 as Any } ?? spelling,
                                                    "b": right.map { $0 as Any } ?? spelling]))
                        let message = try pair(left, right)
                        let label = "\(String(describing: left)) \(comparison) \(String(describing: right))"
                        XCTAssertEqual(evaluate(program, on: message), expected, label)
                        XCTAssertEqual(evaluate(notProgram, on: message), !expected, "NOT " + label)
                    }
                }
            }
        }
    }

    /// Numbers and Booleans ordered and compared as `NSNumber` compares them, with either side missing: `true == 1`,
    /// `0 == NO`, and two missing numbers are `<=` and `>=` each other but not `<`.
    func testFieldNumbersCompareAsNSNumber() throws {
        let numbers: [Int?] = [nil, 0, 1, 5]
        for op in ["==", "!=", "<", "<=", ">", ">="] {
            let ages = try compile("event.exec.executable_age_ms \(op) event.exec.target.euid")
            let flags = try compile("event.exec.target.is_adhoc_signed \(op) event.exec.executable_age_ms")
            let predicate = NSPredicate(format: "a \(op) b")
            for age in numbers {
                for euid in numbers {
                    let message = try exec {
                        $0.executable_age_ms = age
                        $0.target.euid = euid
                    }
                    let expected = predicate.evaluate(with: record(["a": age, "b": euid]))
                    XCTAssertEqual(evaluate(ages, on: message), expected, "\(String(describing: age)) \(op) euid")
                }
                for adhoc in [true, false] {
                    let message = try exec {
                        $0.executable_age_ms = age
                        $0.target.is_adhoc_signed = adhoc
                    }
                    let expected = predicate.evaluate(with: record(["a": adhoc, "b": age]))
                    XCTAssertEqual(evaluate(flags, on: message), expected, "\(adhoc) \(op) \(String(describing: age))")
                }
            }
        }
    }

    /// Two whole numbers past 2^53 that a `Double` holds as one are undetermined, where only `NSNumber` tells them
    /// apart, and two it holds apart are decided.
    func testFieldNumbersPastTwoToThe53AreUndeterminedWhenTheyMeet() throws {
        let past = 1 << 53
        let close = try exec {
            $0.executable_age_ms = past + 1
            $0.target.euid = past
        }
        let apart = try exec {
            $0.executable_age_ms = past + 4
            $0.target.euid = past
        }
        var values = MessageValueCache()
        for op in ["==", "!=", "<", ">="] {
            let program = try compile("event.exec.executable_age_ms \(op) event.exec.target.euid")
            XCTAssertEqual(program.verdict(close, eventType: Self.execType, values: &values), .unknown, op)
            values.reset()
            let expected = NSPredicate(format: "a \(op) b").evaluate(with: ["a": past + 4, "b": past])
            XCTAssertEqual(program.verdict(apart, eventType: Self.execType, values: &values),
                           IndicatorVerdict(expected), op)
            values.reset()
        }
    }

    /// Past Foundation's window, a left side is compared on its first 64 KiB, or its last for `ENDSWITH`, and a match
    /// well inside it stands. A right side past it is undetermined, as is `==` with options of a left one: neither is
    /// ever false.
    func testFieldsPastFoundationsWindow() throws {
        let long = "\u{E9}" + String(repeating: "a", count: StringMatching.foundationLimit) + "Z\u{E9}"
        let verdicts: [(String?, String?, String, IndicatorVerdict)] = [
            (long, "\u{E9}aa", "BEGINSWITH", .yes), (long, "aZ\u{E9}", "ENDSWITH", .yes),
            (long, "\u{E9}ab", "BEGINSWITH", .unknown), (long, long, "==[c]", .unknown),
            ("\u{E9}", long, "BEGINSWITH", .unknown), (long, long, "==", .yes), (long, long + "a", "!=", .yes),
        ]
        for (left, right, comparison, expected) in verdicts {
            var values = MessageValueCache()
            values.scan.limit = .max
            let program = try compile("\(Self.leftField) \(comparison) \(Self.rightField)")
            XCTAssertEqual(program.verdict(try pair(left, right), eventType: Self.execType, values: &values), expected,
                           comparison)
        }
    }
}


// MARK: - Making pairs
extension StringMatchingTests {
    /// - Parameters:
    ///   - left: The script content.
    ///   - right: The exec target's team ID.
    /// - Returns: The synthetic corpus's first exec, with them.
    /// - Throws: The error making the corpus.
    func pair(_ left: String?, _ right: String?) throws -> Message {
        try exec {
            $0.script_content = left
            $0.target.team_id = right
        }
    }

    /// - Parameter values: Keys and their values, `nil` for one that's left out.
    /// - Returns: A record with the keys that have a value.
    func record(_ values: [String: Any?]) -> [String: Any] {
        values.compactMapValues { $0 }
    }
}
