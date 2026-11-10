//
//  StringMatching.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - String matching
/// The string comparisons an ``IndicatorProgram`` makes, each giving what `NSPredicate` gives on the record
/// (`StringMatchingTests` checks every operator and option against it), in time linear in the value however hostile
/// it is.
///
/// - `==`, `!=` and `IN` without options compare UTF-8 bytes: `NSPredicate`'s `==` is literal, so an NFD path isn't
///   its NFC spelling. `IN` is literal with options too, as `NSPredicate` ignores them there.
/// - When the value and the constant are both ASCII, every operator works on bytes, `[c]` folding ASCII letters, and
///   `[d]` doing nothing. A search runs Knuth-Morris-Pratt on the constant's failure table, skipping to the next
///   place its first byte is, so it's O(n + m) whatever the input. `LIKE` matches its pattern's literal segments
///   between `*` from the left: the first anchored, the last at the end, the middle ones searched.
/// - Otherwise Foundation compares, with the rule's options (`StringMatching+Foundation.swift`), on at most
///   ``foundationLimit`` bytes of the value.
///
/// One rule from `NSPredicate`'s `LIKE` holds on both paths: a segment never starts between a carriage return and the
/// line feed after it, which `NSPredicate` reads as one character.
enum StringMatching {
    // MARK: ASCII
    /// Is every byte ASCII? Sixteen bytes at a time.
    ///
    /// - Parameter bytes: The bytes.
    /// - Returns: `true` when none has its high bit set.
    static func isASCII(_ bytes: UnsafeBufferPointer<UInt8>) -> Bool {
        guard let base = bytes.baseAddress else { return true }
        let raw = UnsafeRawPointer(base)
        let high = SIMD16<UInt8>(repeating: 0x80)
        var index = 0
        while index + 16 <= bytes.count {
            if raw.loadUnaligned(fromByteOffset: index, as: SIMD16<UInt8>.self) & high != SIMD16() { return false }
            index += 16
        }
        while index < bytes.count {
            if base[index] >= 0x80 { return false }
            index += 1
        }
        return true
    }

    /// - Parameter string: A string.
    /// - Returns: Whether all of its UTF-8 is ASCII.
    static func isASCII(_ string: Substring) -> Bool {
        withBytes(of: string, isASCII)
    }

    /// Run a body on a string's UTF-8, in place when the string is native, as an event's strings are, or else on a
    /// copy. (A substring's UTF-8 view never offers its storage itself, so `withUTF8` reads it.)
    ///
    /// - Parameters:
    ///   - string: The string.
    ///   - body: Reads its bytes.
    /// - Returns: What `body` returns.
    @inline(__always)
    static func withBytes<Result>(of string: Substring, _ body: (UnsafeBufferPointer<UInt8>) -> Result) -> Result {
        var string = string
        return string.withUTF8(body)
    }

    /// - Parameter byte: An ASCII byte.
    /// - Returns: It in lowercase, if it's a letter.
    @inline(__always)
    static func lowered(_ byte: UInt8) -> UInt8 {
        byte &- 0x41 < 26 ? byte | 0x20 : byte
    }

    /// Are two byte strings the same, folding ASCII letters when asked?
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - constant: The constant, already lowered when folding.
    ///   - folding: Fold the value's letters?
    /// - Returns: Whether they're equal.
    static func equal(_ value: UnsafeBufferPointer<UInt8>, _ constant: UnsafeBufferPointer<UInt8>,
                      folding: Bool) -> Bool {
        value.count == constant.count && matches(value, at: 0, constant, folding: folding)
    }

    /// Does the value start with the constant? An empty constant starts nothing, as `NSPredicate` has it.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - constant: The constant, already lowered when folding.
    ///   - folding: Fold the value's letters?
    /// - Returns: Whether it does.
    static func hasPrefix(_ value: UnsafeBufferPointer<UInt8>, _ constant: UnsafeBufferPointer<UInt8>,
                          folding: Bool) -> Bool {
        !constant.isEmpty && value.count >= constant.count && matches(value, at: 0, constant, folding: folding)
    }

    /// Does the value end with the constant? An empty constant ends nothing.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - constant: The constant, already lowered when folding.
    ///   - folding: Fold the value's letters?
    /// - Returns: Whether it does.
    static func hasSuffix(_ value: UnsafeBufferPointer<UInt8>, _ constant: UnsafeBufferPointer<UInt8>,
                          folding: Bool) -> Bool {
        !constant.isEmpty && value.count >= constant.count
            && matches(value, at: value.count - constant.count, constant, folding: folding)
    }

    /// Does the value contain the constant, within a budget? An empty constant is in nothing.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - constant: The constant, already lowered when folding.
    ///   - failure: The constant's failure table.
    ///   - folding: Fold the value's letters?
    ///   - budget: The units the search may spend, less what it spent.
    /// - Returns: Whether it does, or ``IndicatorVerdict/unknown`` when the budget ran out first.
    static func contains(_ value: UnsafeBufferPointer<UInt8>, _ constant: UnsafeBufferPointer<UInt8>,
                         failure: UnsafeBufferPointer<Int32>, folding: Bool, budget: inout Int) -> IndicatorVerdict {
        guard !constant.isEmpty else { return .no }
        return firstIndex(of: constant, failure: failure, in: value, from: 0, to: value.count, folding: folding,
                          keepsLines: false, budget: &budget).verdict
    }

    /// Do the value's bytes from an offset start with the constant's?
    ///
    /// - Parameters:
    ///   - value: The value, at least `offset + constant.count` long.
    ///   - offset: Where in it.
    ///   - constant: The constant, already lowered when folding.
    ///   - folding: Fold the value's letters?
    /// - Returns: Whether they do.
    @inline(__always)
    static func matches<Unit: FixedWidthInteger>(_ value: UnsafeBufferPointer<Unit>, at offset: Int,
                                                 _ constant: UnsafeBufferPointer<Unit>, folding: Bool) -> Bool {
        guard folding, Unit.self == UInt8.self else {
            for index in 0..<constant.count where value[offset + index] != constant[index] { return false }
            return true
        }
        for index in 0..<constant.count where Unit(lowered(UInt8(truncatingIfNeeded: value[offset + index])))
            != constant[index] { return false }
        return true
    }

    // MARK: Search
    /// A constant's Knuth-Morris-Pratt failure table: for each prefix, the longest proper prefix that's also its
    /// suffix.
    ///
    /// - Parameter pattern: The constant, as it's searched for (lowered when folding).
    /// - Returns: The table, one entry per unit.
    static func failureTable<Unit: Equatable>(of pattern: UnsafeBufferPointer<Unit>) -> [Int32] {
        var table = [Int32](repeating: 0, count: pattern.count)
        var length = 0
        var index = 1
        while index < pattern.count {
            if pattern[index] == pattern[length] {
                length += 1
                table[index] = Int32(length)
                index += 1
            } else if length > 0 {
                length = Int(table[length - 1])
            } else {
                index += 1
            }
        }
        return table
    }

    /// What a search within a budget found.
    enum Scan: Equatable {
        /// The constant, starting here.
        case found(Int)
        /// Not the constant: there's none.
        case absent
        /// Nothing yet: the budget ran out first.
        case exhausted

        /// The search's verdict on whether the value has the constant.
        var verdict: IndicatorVerdict {
            switch self {
            case .found: .yes
            case .absent: .no
            case .exhausted: .unknown
            }
        }
    }

    /// The first place in part of a value that a constant is, by Knuth-Morris-Pratt, with no budget.
    ///
    /// - Parameters:
    ///   - pattern: The constant, not empty, already lowered when folding.
    ///   - failure: Its failure table.
    ///   - value: The value.
    ///   - start: Where the search starts.
    ///   - end: Where a match has to end by.
    ///   - folding: Fold the value's ASCII letters?
    ///   - keepsLines: Refuse a match that starts on a line feed after a carriage return, as `LIKE` does?
    /// - Returns: Where the first match starts, or `nil`.
    static func firstIndex<Unit: FixedWidthInteger>(of pattern: UnsafeBufferPointer<Unit>,
                                                    failure: UnsafeBufferPointer<Int32>,
                                                    in value: UnsafeBufferPointer<Unit>, from start: Int, to end: Int,
                                                    folding: Bool, keepsLines: Bool) -> Int? {
        var budget = Int.max
        guard case .found(let index) = firstIndex(of: pattern, failure: failure, in: value, from: start, to: end,
                                                  folding: folding, keepsLines: keepsLines, budget: &budget) else {
            return nil
        }
        return index
    }

    /// The first place in part of a value that a constant is, by Knuth-Morris-Pratt, within a budget. While nothing
    /// is matched it skips to the next place the constant's first unit is, which for bytes `memchr` or sixteen bytes
    /// at a time finds.
    ///
    /// Each step costs ``ScanCost/step`` and each skip ``ScanCost/jump(_:isByte:)``, and a skip never goes further
    /// than the budget pays for, so the search spends at most its budget, and stops exactly where the same budget
    /// always stops it.
    ///
    /// - Parameters:
    ///   - pattern: The constant, not empty, already lowered when folding.
    ///   - failure: Its failure table.
    ///   - value: The value.
    ///   - start: Where the search starts.
    ///   - end: Where a match has to end by.
    ///   - folding: Fold the value's ASCII letters?
    ///   - keepsLines: Refuse a match that starts on a line feed after a carriage return, as `LIKE` does?
    ///   - budget: The units it may spend, less what it spent.
    /// - Returns: Where the first match starts, that there's none, or that the budget ran out first.
    static func firstIndex<Unit: FixedWidthInteger>(of pattern: UnsafeBufferPointer<Unit>,
                                                    failure: UnsafeBufferPointer<Int32>,
                                                    in value: UnsafeBufferPointer<Unit>, from start: Int, to end: Int,
                                                    folding: Bool, keepsLines: Bool, budget: inout Int) -> Scan {
        let count = pattern.count
        guard count > 0, end - start >= count else { return .absent }
        let isByte = Unit.self == UInt8.self, shift = isByte ? 7 : 2
        let limit = end - count + 1
        var index = start
        var matched = 0
        while index < end {
            if matched == 0 {
                /// A partial match that failed back past the last place a match can start leaves none.
                guard index < limit else { return .absent }
                guard budget > 0 else { return .exhausted }
                let reach = (limit - index) >> shift < budget ? limit : index + (budget - 1) << shift
                let next = nextCandidate(for: pattern[0], in: value, from: index, to: reach, folding: folding)
                budget -= ScanCost.jump(next - index, isByte: isByte)
                index = next
                guard index < limit else { return .absent }
                guard index < reach else { return .exhausted }
            }
            guard budget > 0 else { return .exhausted }
            budget -= ScanCost.step
            let unit = folding ? Unit(lowered(UInt8(truncatingIfNeeded: value[index]))) : value[index]
            if unit == pattern[matched] {
                matched += 1
                index += 1
                guard matched == count else { continue }
                let found = index - count
                if !keepsLines || !isLineFeedAfterReturn(value, at: found) { return .found(found) }
                matched = Int(failure[matched - 1])
            } else if matched > 0 {
                matched = Int(failure[matched - 1])
            } else {
                index += 1
            }
        }
        return .absent
    }

    /// The next place a constant's first unit could match, or `limit`.
    ///
    /// - Parameters:
    ///   - first: The constant's first unit, lowered when folding.
    ///   - value: The value.
    ///   - start: Where to look from.
    ///   - limit: Past the last place to look.
    ///   - folding: Fold the value's ASCII letters?
    /// - Returns: The place, or `limit` when there's none.
    @inline(__always)
    private static func nextCandidate<Unit: FixedWidthInteger>(for first: Unit, in value: UnsafeBufferPointer<Unit>,
                                                               from start: Int, to limit: Int, folding: Bool) -> Int {
        guard start < limit else { return limit }
        guard Unit.self == UInt8.self, let base = value.baseAddress else {
            var index = start
            while index < limit, value[index] != first { index += 1 }
            return index
        }
        let raw = UnsafeRawPointer(base)
        let byte = UInt8(truncatingIfNeeded: first)
        guard folding, byte &- 0x61 < 26 else {
            guard let found = memchr(raw + start, Int32(byte), limit - start) else { return limit }
            return raw.distance(to: UnsafeRawPointer(found))
        }
        /// A letter folded: either case of it, sixteen bytes at a time. `| 0x20` lowers a letter and nothing else
        /// gives `byte`.
        let wanted = SIMD16<UInt8>(repeating: byte), fold = SIMD16<UInt8>(repeating: 0x20)
        var index = start
        while index + 16 <= limit {
            let lanes = raw.loadUnaligned(fromByteOffset: index, as: SIMD16<UInt8>.self) | fold
            if any(lanes .== wanted) { break }
            index += 16
        }
        while index < limit, base[index] | 0x20 != byte { index += 1 }
        return index
    }

    /// Is a place a line feed right after a carriage return, inside what `NSPredicate` reads as one character?
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - index: The place.
    /// - Returns: Whether it is.
    @inline(__always)
    static func isLineFeedAfterReturn<Unit: FixedWidthInteger>(_ value: UnsafeBufferPointer<Unit>,
                                                               at index: Int) -> Bool {
        index > 0 && index < value.count && value[index] == 10 && value[index - 1] == 13
    }

    // MARK: LIKE
    /// Does a value match a `LIKE` pattern of literal segments between `*`, within a budget?
    ///
    /// The pattern is its segments, in order, as splitting it at every `*` gives them: `"/Users/*/Library/*"` is
    /// `/Users/`, `/Library/` and an empty last one. One segment alone is the whole value. The first is anchored at the
    /// start and the last at the end, and each in between is found leftmost after the one before, which is the
    /// leftmost match a `*` pattern can have, so the match is linear. An empty pattern matches nothing. The first and
    /// last are compared in place, at most their length; only the searches spend the budget.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - count: How many segments.
    ///   - folding: Fold the value's ASCII letters?
    ///   - budget: The units its searches may spend, less what they spent.
    ///   - segment: Each segment, already lowered when folding, and its failure table.
    /// - Returns: Whether it matches, or ``IndicatorVerdict/unknown`` when the budget ran out first.
    static func like<Unit: FixedWidthInteger>(
        _ value: UnsafeBufferPointer<Unit>, segments count: Int, folding: Bool, budget: inout Int,
        segment: (Int) -> (pattern: UnsafeBufferPointer<Unit>, failure: UnsafeBufferPointer<Int32>)
    ) -> IndicatorVerdict {
        guard count > 0 else { return .no }
        let first = segment(0).pattern
        guard count > 1 else {
            return IndicatorVerdict(!first.isEmpty && value.count == first.count
                                    && matches(value, at: 0, first, folding: folding))
        }
        let last = segment(count - 1).pattern
        guard value.count >= first.count + last.count, matches(value, at: 0, first, folding: folding) else {
            return .no
        }
        var start = first.count
        var end = value.count
        if !last.isEmpty {
            end = value.count - last.count
            guard matches(value, at: end, last, folding: folding), !isLineFeedAfterReturn(value, at: end) else {
                return .no
            }
        }
        for index in 1..<count - 1 {
            let (pattern, failure) = segment(index)
            guard !pattern.isEmpty else { continue }
            switch firstIndex(of: pattern, failure: failure, in: value, from: start, to: end, folding: folding,
                              keepsLines: true, budget: &budget) {
            case .found(let found): start = found + pattern.count
            case .absent: return .no
            case .exhausted: return .unknown
            }
        }
        return .yes
    }
}
