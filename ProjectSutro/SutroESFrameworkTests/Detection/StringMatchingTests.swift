//
//  StringMatchingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Differential tests against NSPredicate
/// Pins every comparison a compiled indicator makes to `NSPredicate`'s, on the same value and constant: each operator
/// by `[]`, `[c]`, `[d]` and `[cd]`, on ASCII, NFC and NFD strings, an ASCII constant against an NFD value with a
/// combining mark right after the match, the Kelvin sign, the long s, a carriage return and line feed, and empty
/// strings; the nil table; and Booleans, whole numbers and fractions compared as numbers.
final class StringMatchingTests: XCTestCase {
    /// NFC and NFD spellings of "Résumé".
    static let nfc = "R\u{E9}sum\u{E9}", nfd = "Re\u{301}sume\u{301}"
    /// Values: ASCII, accented both ways, the Kelvin sign, the long s, ß, a ligature, an emoji, CR LF, and empty.
    static let values = ["abc", "ABC", "/Users/a/Library/x.plist", nfc, nfd, "Re\u{301}", "\u{212A}elvin", "kelvin",
                         "\u{17F}tar", "star", "", "\u{DF}", "SS", "a\r\nb", "x\u{301}y", "\u{FB01}le",
                         "\u{1F600}x", "ab\u{301}c", "/Users/a/Re\u{301}sume\u{301}/x.PLIST"]
    /// Constants for `==`, `!=`, `BEGINSWITH`, `ENDSWITH`, `CONTAINS` and `IN`.
    static let constants = ["abc", "re", "RE", "Re", "e", "sume", "plist", ".PLIST", "k", "K", "\u{212A}", "s", "ss",
                            nfc, nfd, "resume", "", "a", "\u{E9}", "e\u{301}", "\u{DF}", "KELVIN", "fi", "\n", "\r",
                            "\nb", "x", "y", "ABC", "star"]
    /// `LIKE` patterns, which are ASCII.
    static let patterns = ["*", "Re*", "*e", "*s*", "R*e", "*su*e*", "/Users/*/x*", "*b*c", "a*", "e*", "*x*y*",
                           "**", "abc", "ab", "*ss*", "*plist", "re*", "*E", "*\nb", "a\r*", "*\n*", "*k*", "*K*",
                           "*fi*", "star", "*/Library/*", "*.PLIST", "/users/*"]
    /// Each set of options.
    static let options = ["", "[c]", "[d]", "[cd]"]

    /// `==`, `!=`, `BEGINSWITH`, `ENDSWITH`, `CONTAINS` and `IN`, by every set of options.
    func testComparisonsAreNSPredicates() throws {
        var compared = 0
        for op in ["==", "!=", "BEGINSWITH", "ENDSWITH", "CONTAINS"] {
            for options in Self.options {
                for constant in Self.constants {
                    compared += try assertSame("\(op)\(options) \(literal(constant))", constant: constant)
                }
            }
        }
        for options in Self.options {
            for constant in Self.constants {
                compared += try assertSame("IN\(options) {\(literal(constant)), \"zzz\"}", constant: [constant, "zzz"])
            }
        }
        XCTAssertGreaterThan(compared, 10_000)
    }

    /// `LIKE`, by every set of options.
    func testLikeIsNSPredicates() throws {
        for options in Self.options {
            for pattern in Self.patterns {
                try assertSame("LIKE\(options) \(literal(pattern))", constant: pattern)
            }
        }
    }

    /// A missing value, `nil` or `NSNull`, is compared as `NSPredicate` compares it: `!=` a constant and `== nil` are
    /// true, `!= nil` and every other comparison false, and `NOT` turns each around.
    func testTheNilTable() throws {
        let comparisons = [#"== "x""#, #"!= "x""#, "== nil", "!= nil", #"BEGINSWITH "x""#, #"ENDSWITH "x""#,
                           #"CONTAINS "x""#, #"LIKE "x*""#, #"IN {"x", "y"}"#, #"==[c] "x""#, #"!=[cd] "x""#]
        for comparison in comparisons {
            let program = try compile(Self.field.path + " " + comparison)
            let notProgram = try compile("NOT " + Self.field.path + " " + comparison)
            let message = try exec(script: nil)
            for missing in [nil, NSNull()] as [Any?] {
                let expected = NSPredicate(format: "v " + comparison).evaluate(with: missing.map { ["v": $0] } ?? [:])
                XCTAssertEqual(evaluate(program, on: message), expected, comparison)
                XCTAssertEqual(evaluate(notProgram, on: message), !expected, "NOT " + comparison)
            }
        }
    }

    /// Booleans, whole numbers and fractions compare as numbers, as `NSNumber` does: `true == 1`, `0 == NO`. Ordering
    /// with `nil` is refused (`IndicatorCompilerTests`).
    func testNumbersCoerceAsNSNumber() throws {
        let constants = ["1", "0", "YES", "NO", "TRUE", "FALSE", "1.0", "0.5", "5", "-1", "nil"]
        let comparisons = ["==", "!=", "<", "<=", ">", ">="].flatMap { op in constants.map { "\(op) \($0)" } }
            .filter { !$0.hasSuffix("nil") || $0.hasPrefix("=") || $0.hasPrefix("!") }
            + ["IN {1, 2}", "IN {0}", "IN {5, 0.5}"]
        for comparison in comparisons {
            let flag = try compile("event.exec.target.is_adhoc_signed " + comparison)
            let age = try compile("event.exec.executable_age_ms " + comparison)
            for adhoc in [true, false] {
                let message = try exec { $0.target.is_adhoc_signed = adhoc }
                let expected = NSPredicate(format: "v " + comparison).evaluate(with: ["v": adhoc])
                XCTAssertEqual(evaluate(flag, on: message), expected, "\(adhoc) \(comparison)")
            }
            for milliseconds in [0, 1, 5, nil] as [Int?] {
                let message = try exec { $0.executable_age_ms = milliseconds }
                let record: [String: Any] = milliseconds.map { ["v": $0] } ?? [:]
                let expected = NSPredicate(format: "v " + comparison).evaluate(with: record)
                let label = "\(String(describing: milliseconds)) \(comparison)"
                XCTAssertEqual(evaluate(age, on: message), expected, label)
            }
        }
    }

    /// `ANY` of an exec's environment, as `NSPredicate` compares an array: false when it's empty.
    func testAnyIsNSPredicates() throws {
        let environments = [[], ["a"], ["DYLD_INSERT_LIBRARIES=/tmp/x.dylib", "HOME=/Users/a"], [Self.nfd, "b"],
                            ["\u{212A}=1"], ["a\r\nb"]]
        let comparisons = [#"BEGINSWITH "DYLD_""#, #"== "a""#, #"!= "a""#, #"LIKE "DYLD_*=*.dylib""#,
                           #"CONTAINS[c] "re""#, #"==[c] "k=1""#, #"ENDSWITH[d] "e""#, #"IN {"a", "b"}"#,
                           #"LIKE[c] "*\nb""#]
        for comparison in comparisons {
            let program = try compile("ANY event.exec.env " + comparison)
            for environment in environments {
                let message = try exec { $0.env = environment }
                let expected = NSPredicate(format: "ANY v " + comparison).evaluate(with: ["v": environment])
                XCTAssertEqual(evaluate(program, on: message), expected, "\(environment) \(comparison)")
            }
        }
    }

    /// A non-ASCII value past the Foundation path's limit is compared on its first 64 KiB, or its last for
    /// `ENDSWITH`, and each is counted: a match the window has stands, and one past it is undetermined, not missed.
    /// The budget is unlimited, so only the window decides (`IndicatorVerdictTests` has the window's rules).
    func testFoundationReadsSixtyFourKiB() throws {
        let long = "\u{E9}" + String(repeating: "a", count: StringMatching.foundationLimit) + "Z\u{E9}"
        let message = try exec(script: long)
        var values = MessageValueCache()
        values.scan.limit = .max
        let contains = try compile(Self.field.path + #" CONTAINS[c] "z""#)
        let ends = try compile(Self.field.path + #" ENDSWITH "Z\#u{E9}""#)
        XCTAssertEqual(contains.verdict(message, eventType: Self.execType, values: &values), .unknown)
        XCTAssertEqual(ends.verdict(message, eventType: Self.execType, values: &values), .yes)
        XCTAssertEqual(values.truncatedEvaluations, 2)
        values.reset()
        XCTAssertEqual(try compile(Self.field.path + #" BEGINSWITH "\#u{E9}aa""#)
            .verdict(message, eventType: Self.execType, values: &values), .yes)
        XCTAssertEqual(values.truncatedEvaluations, 3)
    }

    /// A window cut inside a scalar backs off to where it starts: byte 65,536 is the second byte of an "é", the third
    /// of a "€" or the fourth of an emoji, at the first window's end and at the last's start. Each window then holds
    /// whole scalars, and a match well inside it stands for the whole value; without the backoff Foundation couldn't
    /// read the window, and these would come out undetermined. Bytes that aren't UTF-8 make an empty window, still
    /// marked as cut, so a comparison on it is undetermined, never false.
    func testFoundationCutsWhereAScalarStarts() throws {
        let limit = StringMatching.foundationLimit, a = { String(repeating: "a", count: $0) }
        let first = "\u{E9}" + a(limit - 3) + "\u{E9}Z\u{E9}", last = "x\u{E9}" + a(limit - 3) + "\u{E9}"
        let cuts: [(value: String, fromEnd: Bool, window: String)] = [
            (first, false, "\u{E9}" + a(limit - 3)),
            (a(limit - 2) + "\u{20AC}", false, a(limit - 2)),
            (a(limit - 3) + "\u{1F600}x", false, a(limit - 3)),
            (last, true, a(limit - 3) + "\u{E9}"),
            ("\u{1F600}" + a(limit - 1), true, a(limit - 1)),
        ]
        for (value, fromEnd, window) in cuts {
            let cut = Array(value.utf8)[fromEnd ? value.utf8.count - limit : limit]
            XCTAssertEqual(cut & 0xC0, 0x80, "byte \(limit) of \(escaped(String(value.prefix(4)))) starts no scalar")
            let part = StringMatching.foundationString(value[...], fromEnd: fromEnd)
            XCTAssertTrue(part.truncated)
            XCTAssertEqual(part.string as String, window, "\(value.utf8.count) bytes, from the end: \(fromEnd)")
        }
        let verdicts: [(String, String, IndicatorVerdict)] = [
            (first, #" BEGINSWITH "\#u{E9}aa""#, .yes), (first, #" CONTAINS[c] "z""#, .unknown),
            (last, #" ENDSWITH "a\#u{E9}""#, .yes),
        ]
        for (value, comparison, expected) in verdicts {
            var values = MessageValueCache()
            values.scan.limit = .max
            XCTAssertEqual(try compile(Self.field.path + comparison)
                .verdict(try exec(script: value), eventType: Self.execType, values: &values), expected, comparison)
            XCTAssertEqual(values.truncatedEvaluations, 1, comparison)
        }

        let invalid = [UInt8](repeating: 0x61, count: limit + 8)
        for (bytes, fromEnd) in [([0xFF] + invalid, false), (invalid + [0xFF], true)] {
            let part = bytes.withUnsafeBufferPointer { StringMatching.part(of: $0, fromEnd: fromEnd, limit: limit) }
            XCTAssertEqual(part.string, "", "from the end: \(fromEnd)")
            XCTAssertTrue(part.truncated, "from the end: \(fromEnd)")
        }
    }

    /// A value of exactly 64 KiB is read whole: `CONTAINS` and `ENDSWITH` decide on a match right at its end, and
    /// `LIKE` runs, with nothing counted as cut. One byte more and it's a window: the same `CONTAINS` and `LIKE` come
    /// out undetermined, and `ENDSWITH` still decides on the last window. Two windows are cut: the first, for
    /// `CONTAINS`, and the last, for `ENDSWITH`; `LIKE` reads none.
    func testAValueAtTheLimitIsReadWhole() throws {
        let limit = StringMatching.foundationLimit
        let whole = "\u{E9}" + String(repeating: "a", count: limit - 5) + "Z\u{E9}"
        XCTAssertEqual(whole.utf8.count, limit)
        XCTAssertFalse(StringMatching.isTruncated(limit))
        XCTAssertTrue(StringMatching.isTruncated(limit + 1))
        let part = StringMatching.foundationString(whole[...])
        XCTAssertFalse(part.truncated)
        XCTAssertEqual(part.string as String, whole)
        let contains = try compile(Self.field.path + #" CONTAINS[c] "z""#)
        let like = try compile(Self.field.path + #" LIKE[c] "*z*""#)
        let ends = try compile(Self.field.path + #" ENDSWITH "Z\#u{E9}""#)
        var values = MessageValueCache()
        values.scan.limit = .max
        let atLimit = try exec(script: whole)
        for program in [contains, like, ends] {
            XCTAssertEqual(program.verdict(atLimit, eventType: Self.execType, values: &values), .yes)
        }
        XCTAssertEqual(values.truncatedEvaluations, 0)

        values.reset()
        let longer = whole + "a"
        XCTAssertEqual(longer.utf8.count, limit + 1)
        let over = try exec(script: longer)
        XCTAssertEqual(contains.verdict(over, eventType: Self.execType, values: &values), .unknown)
        XCTAssertEqual(like.verdict(over, eventType: Self.execType, values: &values), .unknown)
        XCTAssertEqual(try compile(Self.field.path + #" ENDSWITH "Z\#u{E9}a""#)
            .verdict(over, eventType: Self.execType, values: &values), .yes)
        XCTAssertEqual(values.truncatedEvaluations, 2)
    }

    /// A search within a budget finds what the unbudgeted one does, says there's none where there's none, and stops
    /// as exhausted, never as absent, when its budget runs out first.
    func testBudgetedSearchesSayWhyTheyStopped() {
        let value = Array("abcabcabd".utf8), pattern = Array("abd".utf8)
        value.withUnsafeBufferPointer { value in
            pattern.withUnsafeBufferPointer { pattern in
                let failure = StringMatching.failureTable(of: pattern)
                failure.withUnsafeBufferPointer { failure in
                    /// Searches the value for the pattern within a budget.
                    /// - Parameters:
                    ///   - units: The budget.
                    ///   - end: Where the search stops.
                    /// - Returns: How the search ended.
                    func search(_ units: Int, in end: Int = value.count) -> StringMatching.Scan {
                        var budget = units
                        return StringMatching.firstIndex(of: pattern, failure: failure, in: value, from: 0, to: end,
                                                         folding: false, keepsLines: false, budget: &budget)
                    }
                    XCTAssertEqual(search(.max), .found(6))
                    XCTAssertEqual(search(.max, in: 8), .absent)
                    XCTAssertEqual(search(0), .exhausted)
                    XCTAssertEqual(search(3), .exhausted)
                    XCTAssertEqual(StringMatching.Scan.found(1).verdict, .yes)
                    XCTAssertEqual(StringMatching.Scan.absent.verdict, .no)
                    XCTAssertEqual(StringMatching.Scan.exhausted.verdict, .unknown)
                }
            }
        }
    }
}


// MARK: - Comparing
extension StringMatchingTests {
    /// The field the tests compare: a string that can be missing.
    static let field = IndicatorField.execScriptContent
    /// An exec's type number.
    static let execType = Int(ES_EVENT_TYPE_NOTIFY_EXEC.rawValue)
    /// The synthetic corpus's first exec, made once.
    static let corpusExec = Result {
        try XCTUnwrap(SyntheticCorpus.records().map(\.message)
            .first { $0.es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" })
    }

    /// Check one comparison on every value against `NSPredicate`'s.
    ///
    /// - Parameters:
    ///   - comparison: The operator, its options and its constant, as a predicate writes them.
    ///   - constant: The constant, for `NSPredicate`'s `%@`.
    /// - Returns: How many values it compared.
    /// - Throws: The error compiling it or making an event.
    @discardableResult
    func assertSame(_ comparison: String, constant: Any, file: StaticString = #filePath,
                    line: UInt = #line) throws -> Int {
        let program = try compile(Self.field.path + " " + comparison)
        let format = "v " + comparison.prefix { $0 != " " } + " %@"
        for value in Self.values {
            let expected = NSPredicate(format: format, argumentArray: [constant]).evaluate(with: ["v": value])
            XCTAssertEqual(evaluate(program, on: try exec(script: value)), expected,
                           "\(escaped(value)) \(escaped(comparison))", file: file, line: line)
        }
        return Self.values.count
    }

    /// - Parameter comparison: A comparison of an exec's field.
    /// - Returns: Its program, the exec type check dropped.
    /// - Throws: A failure when it doesn't compile.
    func compile(_ comparison: String) throws -> IndicatorProgram {
        let source = #"es_event_type == "ES_EVENT_TYPE_NOTIFY_EXEC" AND "# + comparison
        switch IndicatorCompiler.compile(source) {
        case .success(let rule): return rule.program
        case .failure(let problem):
            XCTFail("\(comparison) doesn't compile: \(problem)")
            throw problem
        }
    }

    /// - Parameters:
    ///   - program: A program.
    ///   - message: An exec.
    /// - Returns: Its verdict, on a fresh cache.
    func evaluate(_ program: IndicatorProgram, on message: Message) -> Bool {
        var values = MessageValueCache()
        return program.matches(message, eventType: Self.execType, values: &values)
    }

    /// - Parameter script: The script content.
    /// - Returns: The synthetic corpus's first exec, with it.
    /// - Throws: The error making the corpus.
    func exec(script: String?) throws -> Message {
        try exec { $0.script_content = script }
    }

    /// - Parameter change: Changes the exec.
    /// - Returns: The synthetic corpus's first exec, changed.
    /// - Throws: The error making the corpus, or a failure when it has no exec.
    func exec(_ change: (inout ProcessExecEvent) -> Void) throws -> Message {
        var message = try Self.corpusExec.get()
        var exec = try XCTUnwrap(message.event.exec)
        change(&exec)
        message.event = .exec(exec)
        return message
    }

    /// - Parameter string: A constant.
    /// - Returns: It quoted, as a predicate writes it.
    func literal(_ string: String) -> String {
        IndicatorValue.literal(string[...])
    }

    /// - Parameter string: A value or comparison.
    /// - Returns: It with each scalar past ASCII, and each control character, written as its number.
    func escaped(_ string: String) -> String {
        string.unicodeScalars.map { scalar in
            scalar.isASCII && scalar.value >= 0x20 ? String(scalar) : "\\u{\(String(scalar.value, radix: 16))}"
        }
            .joined()
    }
}
