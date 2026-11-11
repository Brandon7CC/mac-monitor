//
//  IndicatorVerdictTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Three-valued verdicts
/// Pins the three-valued verdicts (``IndicatorVerdict``): Kleene's `AND`, `OR` and `NOT`, a budget that never turns a
/// `yes` into a `no`, `ANY` in two passes, and Foundation's 64 KiB window, whose `yes` always stands for the whole
/// value and which is otherwise undetermined.
final class IndicatorVerdictTests: XCTestCase {
    /// Comparisons whose verdict is each value, on ``leafExec()`` with no budget: `unknown` for a search it can't pay
    /// for.
    static let leaves: [(IndicatorVerdict, String)] = [
        (.no, "process.executable.path == nil"), (.yes, "process.executable.path != nil"),
        (.unknown, #"event.exec.command_line CONTAINS "zz""#),
    ]

    /// `AND`, `OR` and `NOT` over `no`, `yes` and `unknown` are Kleene's, whichever side `unknown` is on.
    func testAndOrAndNotAreKleenes() throws {
        let message = try leafExec()
        for (left, a) in Self.leaves {
            XCTAssertEqual(self.verdict(try execProgram("NOT " + a), on: message, limit: 0).0, left.negated, a)
            for (right, b) in Self.leaves {
                let and: IndicatorVerdict = left == .no || right == .no ? .no
                    : left == .unknown || right == .unknown ? .unknown : .yes
                let or: IndicatorVerdict = left == .yes || right == .yes ? .yes
                    : left == .unknown || right == .unknown ? .unknown : .no
                XCTAssertEqual(self.verdict(try execProgram("(\(a) AND \(b))"), on: message, limit: 0).0, and)
                XCTAssertEqual(self.verdict(try execProgram("(\(a) OR \(b))"), on: message, limit: 0).0, or)
            }
        }
    }

    /// `NOT` of a search the budget can't pay for, on a 1 MiB command line, is undetermined, never a hit, and its
    /// rule is listed as the budget's.
    func testNotOfARefusedSearchIsUndetermined() throws {
        let message = try corpusExec { $0.command_line = String(repeating: "a b ", count: 1 << 18) }
        let rule = execIndicator("Not zz", #"NOT event.exec.command_line CONTAINS "zz""#)
        var values = MessageValueCache()
        values.scan.limit = 0
        let evaluation = CompiledIndicators([rule]).evaluate(message, values: &values)
        XCTAssertEqual(evaluation.hits, [])
        XCTAssertEqual(evaluation.undetermined.map(\.hit.id), [rule.id])
        XCTAssertEqual(evaluation.undetermined.first?.reason, .scanBudget)
        XCTAssertEqual(values.scanExhaustedEvents, 1)
        XCTAssertEqual(values.undeterminedEvents, 1)
    }

    /// For random programs and budgets, on the corpus and on long values, every `yes` and `no` is the unlimited
    /// verdict, which is `NSPredicate`'s (`IndicatorFuzzTests`). 500 programs, so more than 1,000 verdicts are decided
    /// however many fields the fuzzer draws from.
    func testABudgetNeverChangesADecidedVerdict() throws {
        let corpus = try SyntheticCorpus.records().map(\.message).filter { $0.event.exec != nil }.prefix(40)
        let messages = Array(corpus)
            + (try [AdversarialEvent.nonascii, .asciiCrafted, .nonasciiEnvXcode].map { try $0.message(self) })
        var fuzzer = PredicateFuzzer(seed: 0x5CA7_0002, messages: messages)
        var generator = SeededGenerator(seed: 0x5CA7_0003)
        var decided = 0, undecided = 0
        for _ in 0..<500 {
            guard case .success(let rule) = IndicatorCompiler.compile(fuzzer.rule()) else { continue }
            for message in messages {
                let type = CompiledIndicators.eventType(of: message)
                guard rule.types.contains(type) else { continue }
                let limit = [0, 1, 3, 50, 700, 9_000, 120_000].randomElement(using: &generator)!
                let unlimited = self.verdict(rule.program, on: message, limit: .max).0
                let budgeted = self.verdict(rule.program, on: message, limit: limit).0
                if budgeted == .unknown { undecided += 1 } else { decided += 1 }
                XCTAssertTrue(budgeted == .unknown || budgeted == unlimited, "\(rule.program) at \(limit)")
            }
        }
        XCTAssertGreaterThan(decided, 1_000)
        XCTAssertGreaterThan(undecided, 50)
    }

    /// The first pass finds an ASCII `DYLD_INSERT_LIBRARIES` after 40,000 non-ASCII variables, with no Foundation
    /// string made. A non-ASCII one there, which the second pass would need Foundation for each variable to find, or
    /// an ASCII one after more variables than the first pass can visit (43,690 short ones, ``ScanCost/element(_:)``),
    /// is undetermined.
    func testAnyLooksAtASCIIElementsFirst() throws {
        let compiled = CompiledIndicators(Indicator.defaults)
        let dylib = try shippedID("Dylib inserted")
        /// Evaluates the shipped set on an exec with this environment.
        /// - Parameter env: The exec's environment variables.
        /// - Returns: The evaluation and the cache it was made with, which holds its counts.
        func evaluate(_ env: [String]) throws -> (IndicatorEvaluation, MessageValueCache) {
            var values = MessageValueCache()
            let evaluation = compiled.evaluate(try corpusExec { $0.env = env }, values: &values)
            return (evaluation, values)
        }
        let (found, values) = try evaluate(Array(repeating: "\u{E9}N", count: 40_000)
                                           + ["DYLD_INSERT_LIBRARIES=/tmp/x.dylib"])
        XCTAssertTrue(found.hits.map(\.id).contains(dylib))
        XCTAssertEqual(found.undetermined, [])
        XCTAssertEqual(values.foundation.stringsMade, 0)
        let (hidden, _) = try evaluate(Array(repeating: "\u{E9}N", count: 40_000)
                                       + ["DYLD_INSERT_LIBRARIES=/tmp/\u{E9}.dylib"])
        XCTAssertEqual(hidden.undetermined.map(\.hit.id), [dylib])
        XCTAssertEqual(hidden.undetermined.first?.reason, .scanBudget)
        let (past, _) = try evaluate(Array(repeating: "AN", count: 87_000) + ["DYLD_INSERT_LIBRARIES=/tmp/x.dylib"])
        XCTAssertFalse(past.hits.map(\.id).contains(dylib))
        XCTAssertEqual(past.undetermined.map(\.hit.id), [dylib])
    }

    /// On a non-ASCII value past the window, with no budget: a match well inside the first window stands, one past
    /// it or within ``StringMatching/windowMargin`` units of its cut is undetermined, `LIKE` and `==[c]` aren't
    /// compared, the reason is the window's, and each window made is still counted.
    func testTheWindowDecidesOnlyWhatItHas() throws {
        let kib = 1 << 10
        /// A non-ASCII script with a literal at one place in it.
        /// - Parameters:
        ///   - literal: The text to place.
        ///   - offset: Its UTF-8 offset in the script.
        ///   - length: The script's UTF-8 length.
        /// - Returns: `é`, then `a`s around the literal, `length` bytes in all.
        func script(_ literal: String, at offset: Int, length: Int = 100 * kib) -> String {
            "\u{E9}" + String(repeating: "a", count: offset - 2) + literal
                + String(repeating: "a", count: length - offset - literal.utf8.count)
        }
        let contains = try execProgram(#"event.exec.script_content CONTAINS "zz""#)
        XCTAssertEqual(try windowed(contains, script("zz", at: 10 * kib)).0, .yes)
        XCTAssertEqual(try windowed(contains, script("zz", at: 90 * kib)).0, .unknown)
        let window = StringMatching.foundationLimit
        XCTAssertEqual(try windowed(contains, script("zz", at: window - 40)).0, .yes)
        XCTAssertEqual(try windowed(contains, script("zz", at: window - 12)).0, .unknown)
        let plist = try execProgram(#"event.exec.script_content LIKE[c] "*.plist""#)
        XCTAssertEqual(try windowed(plist, script(".plist", at: window - 6)).0, .unknown, "today a false positive")
        let equal = try execProgram(#"event.exec.script_content ==[c] "x""#)
        XCTAssertEqual(try windowed(equal, script("x", at: 5)).0, .unknown)
        let rule = execIndicator("Deep", #"event.exec.script_content CONTAINS "zz""#)
        var values = MessageValueCache()
        values.scan.limit = .max
        let message = try corpusExec { $0.script_content = script("zz", at: 90 * kib) }
        let evaluation = CompiledIndicators([rule]).evaluate(message, values: &values)
        XCTAssertEqual(evaluation.undetermined.map(\.reason), [.valueLimit])
        XCTAssertEqual(values.truncatedEvaluations, 1)
        XCTAssertEqual(values.scanExhaustedEvents, 0)
    }

    /// Over random non-ASCII values of 64 to 70 KiB, with combining marks, CR LF, regional indicators, emoji joined
    /// by ZWJ and Hangul jamo about the cut, every `yes` the window gives is Foundation's verdict on the whole value,
    /// and nothing is `no`.
    func testTheWindowsYesIsTheWholeValues() throws {
        var generator = SeededGenerator(seed: 0x5CA7_0004)
        let tricky = ["e", "\u{301}", "\r", "\n", "\u{1F1FA}", "\u{1F1F8}", "\u{1F469}", "\u{200D}", "\u{1F4BB}",
                      "\u{1100}", "\u{1161}", "\u{11A8}", "a", "Z", "\u{E9}"]
        var yes = 0
        for _ in 0..<200 {
            let size = Int.random(in: (64 << 10)...(70 << 10), using: &generator)
            let near = StringMatching.foundationLimit - Int.random(in: 0...96, using: &generator)
            var value = "\u{E9}" + String(repeating: "a", count: near - 2)
            for _ in 0..<64 { value += tricky.randomElement(using: &generator)! }
            value += String(repeating: "b", count: max(0, size - value.utf8.count))
            /// The pieces start at scalar `near - 1`, after "é" and the "a"s: the constant is from about there.
            let scalars = Array(value.unicodeScalars)
            let index = near - 5 + Int.random(in: 0...40, using: &generator)
            let length = Int.random(in: 1...4, using: &generator)
            let constant = String(String.UnicodeScalarView(scalars[index..<index + length]))
            for op in ["CONTAINS", "BEGINSWITH", "ENDSWITH"] {
                let options = ["", "[c]", "[d]", "[cd]"].randomElement(using: &generator)!
                let comparison = "\(op)\(options) " + IndicatorValue.literal(constant[...])
                let program = try execProgram("event.exec.script_content " + comparison)
                let (verdict, _) = try windowed(program, value)
                XCTAssertNotEqual(verdict, .no, comparison)
                guard verdict == .yes else { continue }
                yes += 1
                let whole = NSPredicate(format: "v \(op)\(options) %@", constant).evaluate(with: ["v": value])
                XCTAssertTrue(whole, "\(comparison) near \(near)")
            }
        }
        XCTAssertGreaterThan(yes, 10)
    }
}


// MARK: - Helpers
extension IndicatorVerdictTests {
    /// - Returns: An exec with an executable, and a command line a search has to read.
    /// - Throws: The error making it.
    func leafExec() throws -> Message {
        try corpusExec { $0.command_line = String(repeating: "x y ", count: 64) }
    }

    /// A program's verdict on an exec whose script is a value, with no budget, so only the window decides.
    ///
    /// - Parameters:
    ///   - program: The program.
    ///   - script: The value.
    /// - Returns: The verdict, and the cache after it.
    /// - Throws: The error making the exec.
    func windowed(_ program: IndicatorProgram, _ script: String) throws -> (IndicatorVerdict, MessageValueCache) {
        self.verdict(program, on: try corpusExec { $0.script_content = script }, limit: .max)
    }
}
