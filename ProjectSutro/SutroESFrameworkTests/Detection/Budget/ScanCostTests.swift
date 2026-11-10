//
//  ScanCostTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Foundation's prices
/// Pins what Foundation's comparisons are charged by a value's shape (``ScanCost``, ``ValueShape``): a run of
/// combining marks makes a `[d]` search and `LIKE` cost its square, an anchored comparison its length, and a later,
/// smaller element of an `ANY` is still compared after a larger one was refused. The weights' timing is
/// `IndicatorWeightTests`'.
final class ScanCostTests: XCTestCase {
    /// "D", 2,000 combining acute accents, and " cur": 4,005 bytes, one run of 2,000 scalars that aren't ASCII.
    static let marks = "D" + String(repeating: "\u{301}", count: 2_000) + " cur"

    /// A shape counts the scalars that aren't ASCII, its longest run of them, and the sum of each run's square and of
    /// its first 64's, whatever their UTF-8 lengths. ASCII and CJK ideographs end a run.
    func testAShapeCountsRunsOfScalarsThatArentASCII() {
        XCTAssertEqual(shape("plain ASCII"), ValueShape())
        let mixed = shape("a\u{E9}\u{4E2D}\u{4E2D}\u{301}b\u{1F600}\u{301}\u{316}c\u{E9}")
        XCTAssertEqual([mixed.scalars, mixed.longestRun, mixed.runSquares, mixed.cappedRunSquares],
                       [8, 3, 1 + 1 + 9 + 1, 1 + 1 + 9 + 1])
        let run = shape(Self.marks)
        XCTAssertEqual([run.scalars, run.longestRun, run.runSquares, run.cappedRunSquares],
                       [2_000, 2_000, 4_000_000, 64 * 64])
    }

    /// A `[d]` search of a run of marks is charged its square, so it's refused where the same search with `[c]`, which
    /// takes linear time, is decided, and its string was made, and charged, all the same.
    func testADiacriticInsensitiveSearchOfARunOfMarksIsChargedItsSquare() throws {
        let message = try corpusExec { $0.command_line = Self.marks }
        let folded = verdict(try execProgram(#"event.exec.command_line CONTAINS[c] "curlx""#), on: message)
        XCTAssertEqual(folded.0, .no)
        let diacritics = verdict(try execProgram(#"event.exec.command_line CONTAINS[d] "curlx""#), on: message)
        XCTAssertEqual(diacritics.0, .unknown)
        XCTAssertEqual(diacritics.1.foundation.stringsMade, 1)
        XCTAssertEqual(diacritics.1.scan.refusedPools, 1 << UInt8(ScanPool.commandLine.rawValue))
        XCTAssertGreaterThan(ScanCost.contains(4_005, shape(Self.marks), diacritics: true), ScanBudget.fieldLimit)
        let like = verdict(try execProgram(#"event.exec.command_line LIKE[c] "*curl*""#), on: message)
        XCTAssertEqual(like.0, .unknown)
    }

    /// `BEGINSWITH` and `==` with options are charged the constant and the value's longest run, which bound how far
    /// Foundation reads, exactly.
    func testAnAnchoredComparisonIsChargedItsConstantAndLongestRun() throws {
        let message = try corpusExec { $0.command_line = Self.marks }
        let made = ScanCost.isASCII(4_005) + ScanCost.make(4_005)
        for (comparison, constant) in [(#"BEGINSWITH[d] "DYLD""#, 4), (#"==[cd] "d x""#, 3)] {
            let (verdict, values) = verdict(try execProgram("event.exec.command_line " + comparison), on: message)
            XCTAssertEqual(verdict, .no, comparison)
            XCTAssertEqual(values.scan.spent(from: .commandLine),
                           made + ScanCost.anchored(constant: constant, shape(Self.marks)), comparison)
            XCTAssertEqual(ScanCost.anchored(constant: constant, shape(Self.marks)), 128 + 4 * (constant + 2_000))
        }
    }

    /// `ANY`'s second pass goes on past an element its pool refused: after two 64 KiB variables that aren't ASCII,
    /// the first of which leaves too little for the second, a short `DYLD_INSERT_LIBRARIES` naming a library that
    /// isn't ASCII is still compared, and matches.
    func testAnysSecondPassGoesOnPastARefusal() throws {
        let junk = String(repeating: "\u{E9}a", count: 65_536 / 3)
        let message = try corpusExec { $0.env = [junk, junk, "DYLD_INSERT_LIBRARIES=/tmp/\u{E9}.dylib"] }
        let program = try execProgram(#"ANY event.exec.env BEGINSWITH "DYLD_INSERT_LIBRARIES=""#)
        let (found, values) = verdict(program, on: message)
        XCTAssertEqual(found, .yes)
        XCTAssertEqual(values.foundation.stringsMade, 2)
        XCTAssertTrue(values.scan.refusedThisRule)
        let (missing, _) = verdict(program, on: try corpusExec { $0.env = [junk, junk, "X=\u{E9}"] })
        XCTAssertEqual(missing, .unknown)
    }
}


// MARK: - Helpers
extension ScanCostTests {
    /// - Parameter string: A value.
    /// - Returns: Its shape.
    func shape(_ string: String) -> ValueShape {
        StringMatching.withBytes(of: string[...]) { ValueShape(of: $0) }
    }
}
