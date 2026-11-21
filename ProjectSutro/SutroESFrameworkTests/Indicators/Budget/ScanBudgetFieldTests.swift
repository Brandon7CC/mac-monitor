//
//  ScanBudgetFieldTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Field comparisons within the budget
/// Pins what a field compared with another field costs an event (``ScanBudget``, ``ScanCost``): both fields' reads
/// count, each in its own pool, the comparison counts against both pools once, and a comparison that doesn't fit is
/// undetermined, never false, alone, under `NOT` and in a set.
final class ScanBudgetFieldTests: XCTestCase {
    /// 4 KiB of ASCII on each side of a comparison of the exec target's team and signing IDs, both of the other
    /// fields' pool.
    static let ascii = String(repeating: "a", count: 4_096)

    /// A paired charge is spent from the event once, and counts against each pool's own ceiling and the large fields'
    /// together once. One that doesn't fit a pool spends nothing and notes that pool refused.
    func testAPairedChargeCountsAgainstBothPools() {
        var budget = ScanBudget()
        budget.limit = 1_000
        XCTAssertTrue(budget.charge(400, from: .commandLine, and: .script))
        XCTAssertEqual(budget.spent, 400)
        XCTAssertEqual(budget.spent(from: .commandLine), 400)
        XCTAssertEqual(budget.spent(from: .script), 400)
        XCTAssertEqual(budget.largeSpent, 400)
        XCTAssertFalse(budget.charge(200, from: .other, and: .commandLine))
        XCTAssertEqual(budget.refusedPools, 1 << UInt8(ScanPool.commandLine.rawValue))
        XCTAssertEqual(budget.spent, 400)
        XCTAssertFalse(budget.charge(300, from: .env, and: .other), "the large fields have 225 left together")
        XCTAssertTrue(budget.refusedPools & 1 << UInt8(ScanPool.env.rawValue) != 0)
        XCTAssertTrue(budget.charge(200, from: .other, and: .env))
        XCTAssertEqual(budget.spent(from: .env), 200)
        XCTAssertEqual(budget.largeSpent, 600)
        XCTAssertTrue(budget.charge(100, from: .other, and: .other))
        XCTAssertEqual(budget.spent, 700)
        XCTAssertEqual(budget.refusals, 2)
    }

    /// `==` of two ASCII values without options compares bytes, charged its length once, and with `[c]` both values'
    /// ASCII checks are charged too, each to its own pool. Values of two lengths are decided for nothing.
    func testBothReadsAreCharged() throws {
        let message = try corpusExec {
            $0.command_line = Self.ascii
            $0.script_content = Self.ascii
        }
        let plain = verdict(try execProgram("event.exec.command_line == event.exec.script_content"), on: message)
        XCTAssertEqual(plain.0, .yes)
        XCTAssertEqual(plain.1.scan.spent, ScanCost.pair(4_096))
        XCTAssertEqual(plain.1.scan.spent(from: .commandLine), ScanCost.pair(4_096))
        XCTAssertEqual(plain.1.scan.spent(from: .script), ScanCost.pair(4_096))
        let folded = verdict(try execProgram("event.exec.command_line ==[c] event.exec.script_content"), on: message)
        XCTAssertEqual(folded.0, .yes)
        let checked = ScanCost.isASCII(4_096)
        XCTAssertEqual(folded.1.scan.spent, 2 * checked + ScanCost.pair(4_096))
        XCTAssertEqual(folded.1.scan.spent(from: .commandLine), checked + ScanCost.pair(4_096))
        XCTAssertEqual(folded.1.scan.spent(from: .script), checked + ScanCost.pair(4_096))
        let shorter = try corpusExec {
            $0.command_line = Self.ascii
            $0.script_content = String(Self.ascii.dropLast())
        }
        let decided = verdict(try execProgram("event.exec.command_line != event.exec.script_content"), on: shorter)
        XCTAssertEqual(decided.0, .yes)
        XCTAssertEqual(decided.1.scan.spent, 0)
    }

    /// Below the comparison's cost it's undetermined, its pool noted refused, and so is its `NOT`: never false. At
    /// its cost it's decided.
    func testAComparisonPastTheBudgetIsUndetermined() throws {
        let message = try corpusExec {
            $0.target.team_id = Self.ascii
            $0.target.signing_id = Self.ascii
        }
        let cost = ScanCost.pair(4_096)
        let equal = try execProgram("event.exec.target.team_id == event.exec.target.signing_id")
        let notEqual = try execProgram("NOT event.exec.target.team_id == event.exec.target.signing_id")
        for limit in [0, 1, cost - 1] {
            let (verdict, values) = verdict(equal, on: message, limit: limit)
            XCTAssertEqual(verdict, .unknown, "\(limit)")
            XCTAssertTrue(values.scan.refusedThisRule, "\(limit)")
            XCTAssertEqual(values.scan.refusedPools, 1 << UInt8(ScanPool.other.rawValue))
            XCTAssertEqual(values.scan.spent, 0)
            XCTAssertEqual(self.verdict(notEqual, on: message, limit: limit).0, .unknown, "NOT at \(limit)")
        }
        XCTAssertEqual(verdict(equal, on: message, limit: cost).0, .yes)
        XCTAssertEqual(verdict(notEqual, on: message, limit: cost).0, .no)
    }

    /// Values that aren't ASCII are made into `NSString`s, each charged to its own field's pool, and with too little
    /// left for the first, none is made and the comparison is undetermined. A left side that isn't ASCII sends the
    /// comparison to Foundation without the right side's ASCII check.
    func testFoundationsStringsAreChargedToEachField() throws {
        let accented = String(repeating: "\u{E9}", count: 1_000)
        let message = try corpusExec {
            $0.command_line = accented
            $0.target.team_id = accented
        }
        let program = try execProgram("event.exec.command_line ==[c] event.exec.target.team_id")
        let (decided, values) = verdict(program, on: message)
        XCTAssertEqual(decided, .yes)
        XCTAssertEqual(values.foundation.stringsMade, 2)
        let made = ScanCost.make(2_000), checked = ScanCost.isASCII(2_000)
        let shape = StringMatching.foundationString(accented[...]).shape
        let compared = ScanCost.anchoredPair(2_000, shape, shape, diacritics: false)
        XCTAssertEqual(values.scan.spent(from: .commandLine), checked + made + compared)
        XCTAssertEqual(values.scan.spent, checked + 2 * made + compared)
        let starved = verdict(program, on: message, limit: checked + made)
        XCTAssertEqual(starved.0, .unknown)
        XCTAssertEqual(starved.1.foundation.stringsMade, 0)
        XCTAssertTrue(starved.1.scan.refusedThisRule)
    }

    /// In a set, a field comparison the budget refused is listed undetermined, for the scan budget, and its `NOT`
    /// too, never dropped, while a rule decided without reading anything is a hit.
    func testASetListsARefusedFieldComparisonUndetermined() throws {
        let message = try corpusExec {
            $0.target.team_id = Self.ascii
            $0.target.signing_id = Self.ascii
        }
        let same = execIndicator("Same", "event.exec.target.team_id == event.exec.target.signing_id")
        let differs = execIndicator("Differs", "NOT event.exec.target.team_id == event.exec.target.signing_id")
        let every = execIndicator("Every", "TRUEPREDICATE")
        let compiled = CompiledIndicators([same, differs, every])
        var values = MessageValueCache()
        values.scan.limit = 64
        let evaluation = compiled.evaluate(message, values: &values)
        XCTAssertEqual(evaluation.undetermined.map(\.hit.name), ["Same", "Differs"])
        XCTAssertEqual(Set(evaluation.undetermined.map(\.reason)), [.scanBudget])
        XCTAssertEqual(evaluation.hits.map(\.name), ["Every"])
        values.scan.limit = .max
        XCTAssertEqual(compiled.evaluate(message, values: &values).hits.map(\.name), ["Same", "Every"])
    }
}
