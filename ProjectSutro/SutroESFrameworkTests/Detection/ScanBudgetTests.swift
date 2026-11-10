//
//  ScanBudgetTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Scan budget
/// Pins ``ScanBudget``: its pools' guarantees whatever order they're spent in, the budgeted search's exact stop and
/// charge, Foundation refused before it runs, its cache charged once, and the same event always spending the same.
final class ScanBudgetTests: XCTestCase {
    /// Spent to its ceiling in every order, an event's pools never spend past its limit, the index never past its
    /// eighth, a large field past its half or the three past five eighths, and no allowance is ever negative. Every
    /// other field keeps a quarter whatever the large ones and the index spend, and nearly all of it when they spend
    /// nothing. One padded large field leaves the other two an eighth.
    func testThePoolsKeepTheirGuaranteesInEveryOrder() {
        let large: [ScanPool] = [.commandLine, .env, .script]
        for order in permutations(ScanPool.allCases) {
            var scan = ScanBudget()
            for pool in order {
                if pool == .other {
                    let floor = order.prefix { $0 != .other }.contains(where: \.isLarge)
                        ? ScanBudget.eventLimit / 4 : ScanBudget.eventLimit - ScanBudget.indexLimit
                    XCTAssertGreaterThanOrEqual(scan.allowance(.other), floor, "\(order)")
                }
                if pool.isLarge, large.filter({ scan.spent(from: $0) > 0 }).count == 1,
                   !order.prefix(while: { $0 != pool }).contains(.other) {
                    XCTAssertGreaterThanOrEqual(scan.allowance(pool), ScanBudget.indexLimit, "\(order)")
                }
                scan.spend(scan.allowance(pool), from: pool)
                for each in ScanPool.allCases { XCTAssertGreaterThanOrEqual(scan.allowance(each), 0) }
                XCTAssertFalse(scan.charge(1, from: pool), "\(pool) in \(order)")
            }
            XCTAssertEqual(scan.spent, ScanBudget.eventLimit, "\(order)")
            XCTAssertLessThanOrEqual(scan.spent(from: .index), ScanBudget.indexLimit)
            XCTAssertLessThanOrEqual(scan.largeSpent, ScanBudget.largeLimit)
            for pool in large { XCTAssertLessThanOrEqual(scan.spent(from: pool), ScanBudget.fieldLimit) }
            XCTAssertTrue(scan.refusedThisEvent)
        }
    }

    /// A charge that fits spends it. One that doesn't spends nothing and is noted for the rule and the event, and a
    /// new rule's refusals are its own. Setting the limit starts a new event, with each ceiling the same fraction.
    func testChargesAndRefusals() {
        var scan = ScanBudget()
        XCTAssertTrue(scan.charge(100, from: .env))
        XCTAssertEqual(scan.spent(from: .env), 100)
        XCTAssertFalse(scan.charge(ScanBudget.fieldLimit, from: .env))
        XCTAssertEqual(scan.spent, 100)
        XCTAssertTrue(scan.refusedThisRule)
        XCTAssertEqual(scan.refusedPools, 1 << UInt8(ScanPool.env.rawValue))
        scan.beginRule()
        XCTAssertFalse(scan.refusedThisRule)
        XCTAssertTrue(scan.refusedThisEvent)
        scan.limit = 800
        XCTAssertEqual(scan.spent, 0)
        XCTAssertFalse(scan.refusedThisEvent)
        XCTAssertEqual([ScanPool.index, .commandLine, .other].map(scan.allowance), [100, 400, 800])
        scan.spendUnconditionally(1_000, from: .script)
        XCTAssertEqual(ScanPool.allCases.map(scan.allowance), [0, 0, 0, 0, 0])
        XCTAssertEqual(ScanPool.names(0), "none")
        XCTAssertEqual(ScanPool.names(0b11), "index, commandLine")
    }

    /// With no budget the search finds what a plain search does, over random values and patterns, folded or not,
    /// keeping lines or not, bytes and UTF-16 units, empty and one-unit patterns. With a budget it finds the same or
    /// says it ran out, never more than it may spend, and once found, a larger budget finds the same.
    func testTheBudgetedSearchIsExactAndStopsWithinItsBudget() {
        var generator = SeededGenerator(seed: 0x5CA7_0001)
        let alphabet: [UInt8] = Array("abAB\r\n /".utf8)
        for _ in 0..<3_000 {
            let length = Int.random(in: 0...300, using: &generator)
            let value = (0..<length).map { _ in alphabet.randomElement(using: &generator)! }
            let count = Int.random(in: 0...4, using: &generator)
            var pattern = (0..<count).map { _ in alphabet.randomElement(using: &generator)! }
            let folding = Bool.random(using: &generator), keepsLines = Bool.random(using: &generator)
            if folding { pattern = pattern.map(StringMatching.lowered) }
            let budgets = [0, 1, 2, 5, 40, Int.random(in: 0...400, using: &generator), .max]
            assertSearches(value, pattern, folding: folding, keepsLines: keepsLines, budgets: budgets)
            assertSearches(value.map(UInt16.init), pattern.map(UInt16.init), folding: false, keepsLines: keepsLines,
                           budgets: budgets)
        }
    }

    /// The search charges one unit a step, and for each skip one more and one per 128 bytes it skipped (per 4 units
    /// of UTF-16), and a skip never reads further than its budget pays for.
    func testTheSearchChargesItsStepsAndSkips() {
        let pattern = Array("ab".utf8)
        let far = [UInt8](repeating: UInt8(ascii: "x"), count: 1_000) + pattern
        XCTAssertEqual(search(far, pattern, budget: .max).spent, 1 + 1_000 >> 7 + 2)
        XCTAssertEqual(search(far, pattern, budget: .max).scan, .found(1_000))
        XCTAssertEqual(search(far, pattern, budget: 9).scan, .exhausted)
        XCTAssertEqual(search(far, pattern, budget: 10).scan, .found(1_000))
        var short = [UInt8](repeating: UInt8(ascii: "x"), count: 600)
        short.replaceSubrange(300..<302, with: pattern)
        let three = search(short, pattern, budget: 3)
        XCTAssertEqual(three.scan, .exhausted, "its skip went past the (3 - 1) × 128 bytes 3 units pay for")
        XCTAssertEqual(three.spent, 3)
        XCTAssertEqual(search(short, pattern, budget: 5).scan, .found(300))
        XCTAssertEqual(search(short, pattern, budget: 5).spent, 5)
        let wide = far.map(UInt16.init)
        XCTAssertEqual(search(wide, wide.suffix(2).map { $0 }, budget: .max).spent, 1 + 1_000 >> 2 + 2)
    }

    /// A partial match that fails back to nothing past the last place a match can start ends the search there, with
    /// no jump charged: one jump backwards would refund units. Here a 1,025-byte constant's first 1,000 bytes match,
    /// and the failures fall back one step at a time.
    func testASearchThatFailsPastItsLastStartRefundsNothing() {
        let a = UInt8(ascii: "a")
        let pattern = [UInt8](repeating: a, count: 1_024) + [UInt8(ascii: "b")]
        let value = [UInt8](repeating: a, count: 1_000) + [UInt8(ascii: "x")] + [UInt8](repeating: a, count: 100)
        let found = search(value, pattern, budget: .max)
        XCTAssertEqual(found.scan, .absent)
        XCTAssertEqual(found.spent, 1 + 1_000 + 1_000)
        XCTAssertEqual(search(value, pattern, budget: 2_001).scan, .absent)
        XCTAssertEqual(search(value, pattern, budget: 2_000).scan, .exhausted)
    }

    /// A Foundation comparison whose cost doesn't fit makes no `NSString`, and leaves the rule refused, undetermined.
    func testFoundationIsRefusedBeforeItRuns() throws {
        let message = try corpusExec { $0.script_content = "\u{E9}" + String(repeating: "a", count: 10_000) }
        let program = try execProgram(#"event.exec.script_content CONTAINS "zz""#)
        let (verdict, values) = self.verdict(program, on: message, limit: 1_000)
        XCTAssertEqual(verdict, .unknown)
        XCTAssertEqual(values.foundation.stringsMade, 0)
        XCTAssertTrue(values.scan.refusedThisRule)
        XCTAssertEqual(values.scan.refusedPools, 1 << UInt8(ScanPool.script.rawValue))
        let (unlimited, made) = self.verdict(program, on: message, limit: .max)
        XCTAssertEqual(unlimited, .no)
        XCTAssertEqual(made.foundation.stringsMade, 1)
    }

    /// A field's Foundation string and its `LIKE` units are each charged once per event, however many comparisons
    /// read them, by its shape. An `ANY` element's are charged each time. `ENDSWITH` shares the string of a value
    /// within the window, and has one of its own, its last window, past it.
    func testTheCacheIsChargedOnce() throws {
        let bytes = 2_001
        let script = "\u{E9}" + String(repeating: "a", count: bytes - 2)
        let message = try corpusExec { $0.script_content = script }
        let twice = try execProgram(#"(event.exec.script_content CONTAINS "x" OR event.exec.script_content "#
                                    + #"CONTAINS "y" OR event.exec.script_content LIKE "*x*" OR "#
                                    + #"event.exec.script_content LIKE "*y*")"#)
        let (verdict, values) = self.verdict(twice, on: message, limit: .max)
        XCTAssertEqual(verdict, .no)
        XCTAssertEqual(values.foundation.stringsMade, 1)
        let units = values.scan.spent(from: .script) - ScanCost.isASCII(bytes)
        let shape = StringMatching.withBytes(of: script[...]) { ValueShape(of: $0) }
        let charged = ScanCost.make(bytes) + 2 * ScanCost.contains(bytes, shape, diacritics: false)
            + ScanCost.likeUnits(bytes, shape) + 2 * ScanCost.likeCall
        XCTAssertGreaterThanOrEqual(units, charged)
        XCTAssertLessThan(units, charged + 2 * bytes, "Only the LIKE searches' steps are on top")
        let env = try corpusExec { $0.env = ["\u{E9}=1", "\u{E9}=2"] }
        let (_, elements) = self.verdict(try execProgram(#"ANY event.exec.env CONTAINS "x""#), on: env, limit: .max)
        XCTAssertEqual(elements.foundation.stringsMade, 2)
        let both = try execProgram(#"(event.exec.script_content ENDSWITH[c] "x" OR "#
                                   + #"event.exec.script_content CONTAINS[c] "y")"#)
        XCTAssertEqual(self.verdict(both, on: message, limit: .max).1.foundation.stringsMade, 1)
        let long = try corpusExec { $0.script_content = "\u{E9}" + String(repeating: "a", count: 70_000) }
        XCTAssertEqual(self.verdict(both, on: long, limit: .max).1.foundation.stringsMade, 2)
    }

    /// The same event and set, evaluated 100 times, give the same hits, undetermined indicators and reasons, and
    /// spend the same units.
    func testTheSameEventAlwaysSpendsTheSame() throws {
        let compiled = CompiledIndicators(Indicator.defaults)
        for event in [AdversarialEvent.nonasciiCrafted, .max] {
            let message = try event.message(self)
            var values = MessageValueCache()
            let first = compiled.evaluate(message, values: &values), units = values.lastEventUnits
            XCTAssertFalse(first.undetermined.isEmpty)
            for _ in 0..<100 {
                XCTAssertEqual(compiled.evaluate(message, values: &values), first)
                XCTAssertEqual(values.lastEventUnits, units)
            }
        }
    }
}


// MARK: - Helpers
extension ScanBudgetTests {
    /// - Parameter items: Some items.
    /// - Returns: Every order of them.
    func permutations<Item>(_ items: [Item]) -> [[Item]] {
        guard items.count > 1 else { return [items] }
        return items.indices.flatMap { index -> [[Item]] in
            var rest = items
            let first = rest.remove(at: index)
            return permutations(rest).map { [first] + $0 }
        }
    }

    /// Search a value within a budget.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - pattern: The constant, not empty.
    ///   - budget: The units it may spend.
    ///   - folding: Fold the value's letters?
    ///   - keepsLines: Refuse a match on a line feed after a carriage return?
    /// - Returns: What it found, and the units it spent.
    func search<Unit: FixedWidthInteger>(_ value: [Unit], _ pattern: [Unit], budget: Int, folding: Bool = false,
                                         keepsLines: Bool = false) -> (scan: StringMatching.Scan, spent: Int) {
        value.withUnsafeBufferPointer { value in
            pattern.withUnsafeBufferPointer { pattern in
                StringMatching.failureTable(of: pattern).withUnsafeBufferPointer { failure in
                    var left = budget
                    let scan = StringMatching.firstIndex(of: pattern, failure: failure, in: value, from: 0,
                                                         to: value.count, folding: folding, keepsLines: keepsLines,
                                                         budget: &left)
                    return (scan, budget - left)
                }
            }
        }
    }

    /// Check a search against a plain one at each budget.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - pattern: The constant, lowered when folding.
    ///   - folding: Fold the value's letters?
    ///   - keepsLines: Refuse a match on a line feed after a carriage return?
    ///   - budgets: The budgets to try.
    func assertSearches<Unit: FixedWidthInteger>(_ value: [Unit], _ pattern: [Unit], folding: Bool, keepsLines: Bool,
                                                 budgets: [Int], file: StaticString = #filePath, line: UInt = #line) {
        let expected = plainSearch(value, pattern, folding: folding, keepsLines: keepsLines)
        var decided: StringMatching.Scan?
        for budget in budgets.sorted() {
            guard !pattern.isEmpty else { continue }
            let (scan, spent) = search(value, pattern, budget: budget, folding: folding, keepsLines: keepsLines)
            XCTAssertLessThanOrEqual(spent, budget, file: file, line: line)
            if let decided { XCTAssertEqual(scan, decided, "a larger budget changed it", file: file, line: line) }
            switch scan {
            case .found(let index): XCTAssertEqual(index, expected, file: file, line: line)
            case .absent: XCTAssertNil(expected, file: file, line: line)
            case .exhausted:
                XCTAssertEqual(spent, budget, "it stopped before its budget ran out", file: file, line: line)
                XCTAssertNotEqual(budget, .max, file: file, line: line)
            }
            if scan != .exhausted { decided = scan }
        }
        let unbudgeted = value.withUnsafeBufferPointer { value in
            pattern.withUnsafeBufferPointer { pattern in
                StringMatching.failureTable(of: pattern).withUnsafeBufferPointer { failure in
                    pattern.isEmpty ? nil : StringMatching.firstIndex(of: pattern, failure: failure, in: value, from: 0,
                                                                      to: value.count, folding: folding,
                                                                      keepsLines: keepsLines)
                }
            }
        }
        XCTAssertEqual(unbudgeted, pattern.isEmpty ? nil : expected, file: file, line: line)
    }

    /// - Parameters:
    ///   - value: A value.
    ///   - pattern: A constant, lowered when folding.
    ///   - folding: Fold the value's ASCII letters?
    ///   - keepsLines: Refuse a match on a line feed after a carriage return?
    /// - Returns: Where the constant first is, by trying every place.
    func plainSearch<Unit: FixedWidthInteger>(_ value: [Unit], _ pattern: [Unit], folding: Bool,
                                              keepsLines: Bool) -> Int? {
        guard !pattern.isEmpty, value.count >= pattern.count else { return nil }
        return (0...value.count - pattern.count).first { start in
            let matches = pattern.indices.allSatisfy { offset in
                let unit = value[start + offset]
                return (folding ? Unit(StringMatching.lowered(UInt8(truncatingIfNeeded: unit))) : unit)
                    == pattern[offset]
            }
            let splits = keepsLines && start > 0 && value[start] == 10 && value[start - 1] == 13
            return matches && !splits
        }
    }
}
