//
//  StringMatching+Pairs.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Comparing two values
/// The byte comparisons of one field's value with another's (`IndicatorProgram+Fields.swift`). Unlike a constant,
/// neither side is lowered ahead of time, so `[c]` folds the ASCII letters of both. Each reads at most the right
/// side's length of the left, which its caller charges before it runs (``ScanCost/pair(_:)``).
extension StringMatching {
    /// Are two values the same bytes, folding both sides' ASCII letters when asked?
    ///
    /// - Parameters:
    ///   - left: The left side's value.
    ///   - right: The right side's value.
    ///   - folding: Fold both sides' letters?
    /// - Returns: Whether they're equal.
    static func equalPair(_ left: UnsafeBufferPointer<UInt8>, _ right: UnsafeBufferPointer<UInt8>,
                          folding: Bool) -> Bool {
        left.count == right.count && matchesPair(left, at: 0, right, folding: folding)
    }

    /// Does the left side start with the right? An empty right side starts nothing, as `NSPredicate` has it.
    ///
    /// - Parameters:
    ///   - left: The left side's value.
    ///   - right: The right side's value.
    ///   - folding: Fold both sides' letters?
    /// - Returns: Whether it does.
    static func hasPrefixPair(_ left: UnsafeBufferPointer<UInt8>, _ right: UnsafeBufferPointer<UInt8>,
                              folding: Bool) -> Bool {
        !right.isEmpty && left.count >= right.count && matchesPair(left, at: 0, right, folding: folding)
    }

    /// Does the left side end with the right? An empty right side ends nothing.
    ///
    /// - Parameters:
    ///   - left: The left side's value.
    ///   - right: The right side's value.
    ///   - folding: Fold both sides' letters?
    /// - Returns: Whether it does.
    static func hasSuffixPair(_ left: UnsafeBufferPointer<UInt8>, _ right: UnsafeBufferPointer<UInt8>,
                              folding: Bool) -> Bool {
        !right.isEmpty && left.count >= right.count
            && matchesPair(left, at: left.count - right.count, right, folding: folding)
    }

    /// Do the left side's bytes from an offset start with the right side's? Without folding, `memcmp` compares
    /// them, and folding, sixteen bytes at a time.
    ///
    /// - Parameters:
    ///   - left: The left side's value, at least `offset + right.count` long.
    ///   - offset: Where in it.
    ///   - right: The right side's value.
    ///   - folding: Fold both sides' letters?
    /// - Returns: Whether they do.
    @inline(__always)
    static func matchesPair(_ left: UnsafeBufferPointer<UInt8>, at offset: Int, _ right: UnsafeBufferPointer<UInt8>,
                            folding: Bool) -> Bool {
        guard !right.isEmpty else { return true }
        guard let leftBase = left.baseAddress, let rightBase = right.baseAddress else { return false }
        guard folding else { return memcmp(leftBase + offset, rightBase, right.count) == 0 }
        let leftRaw = UnsafeRawPointer(leftBase + offset), rightRaw = UnsafeRawPointer(rightBase)
        var index = 0
        while index + 16 <= right.count {
            let leftLanes = leftRaw.loadUnaligned(fromByteOffset: index, as: SIMD16<UInt8>.self)
            let rightLanes = rightRaw.loadUnaligned(fromByteOffset: index, as: SIMD16<UInt8>.self)
            if leftLanes != rightLanes, any(lowered(leftLanes) .!= lowered(rightLanes)) { return false }
            index += 16
        }
        while index < right.count {
            if lowered(leftBase[offset + index]) != lowered(rightBase[index]) { return false }
            index += 1
        }
        return true
    }

    /// - Parameter lanes: Sixteen ASCII bytes.
    /// - Returns: Them with each letter in lowercase, as ``lowered(_:)`` lowers one.
    @inline(__always)
    private static func lowered(_ lanes: SIMD16<UInt8>) -> SIMD16<UInt8> {
        let isUpper = (lanes &- SIMD16(repeating: 0x41)) .< SIMD16(repeating: 26)
        return lanes.replacing(with: lanes | SIMD16(repeating: 0x20), where: isUpper)
    }
}
