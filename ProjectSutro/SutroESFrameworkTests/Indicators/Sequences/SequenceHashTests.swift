//
//  SequenceHashTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Sequence hashes
/// Pins ``SequenceHash``: two values are one hash exactly when `==` without options calls them equal, values never
/// run together, a missing value ties nothing, and a chain stays about 100 bytes.
final class SequenceHashTests: XCTestCase {
    /// - Parameter values: Values, in order.
    /// - Returns: Their hash, or `nil` when one is missing.
    private func hash(_ values: IndicatorValue...) -> SequenceHash? {
        var hasher = SequenceHasher()
        for value in values where !hasher.combine(value) { return nil }
        return hasher.finalize()
    }

    /// Equal values are one hash: the same bytes, `0` and `-0`, and a Boolean and its number.
    func testEqualValuesAreOneHash() {
        XCTAssertEqual(hash(.string("/tmp/a")), hash(.string("/tmp/a")))
        XCTAssertEqual(hash(.number(0, isInteger: true)), hash(.number(-0.0, isInteger: false)))
        XCTAssertEqual(hash(IndicatorValue(true)), hash(.number(1, isInteger: true)))
        XCTAssertEqual(hash(.strings(["a", "b"])), hash(.strings(["a", "b"])))
    }

    /// Values that differ, by kind, bytes or where one ends, are different hashes. A missing value is none.
    func testDifferentValuesAreDifferentHashes() {
        let pairs: [(SequenceHash?, SequenceHash?)] = [
            (hash(.string("1")), hash(.number(1, isInteger: true))),
            (hash(.string("ab"), .string("c")), hash(.string("a"), .string("bc"))),
            (hash(.strings(["ab", "c"])), hash(.strings(["a", "bc"]))),
            (hash(.string("e\u{301}")), hash(.string("\u{E9}"))),
            (hash(.string("a")), hash(.strings(["a"]))),
        ]
        for (index, (left, right)) in pairs.enumerated() {
            XCTAssertNotNil(left)
            XCTAssertNotEqual(left, right, "\(index)")
        }
        XCTAssertNil(hash(.string("a"), .null))
    }

    /// A chain is small enough that a full table is a few MiB.
    func testAChainIsAboutAHundredBytes() {
        XCTAssertLessThanOrEqual(MemoryLayout<SequenceChains.Chain>.stride, 96)
        XCTAssertLessThanOrEqual(MemoryLayout<SequenceChains.Key>.stride, 24)
    }
}
