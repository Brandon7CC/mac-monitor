//
//  ScanCost.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Costs
/// What each metered operation costs, in scan units, each measured on an M5 at `-O` to take at most 3 ns a unit
/// (`IndicatorPerformanceTests` checks the ratio on the hostile events, and on each Foundation weight over hostile
/// text). "Bytes" is the UTF-8 length of what's read, or handed to Foundation, which is known before it runs.
///
/// Foundation's costs grow with what a value is made of as well as with its length (``ValueShape``):
///
/// - a scalar that isn't ASCII costs a search more than its bytes do.
/// - a diacritic-insensitive (`[d]`) search takes time quadratic in each run of combining marks.
/// - `ENDSWITH` reorders each run of marks in a buffer of 64, in time quadratic in the part of it that fits, so a
///   value of many runs of 64 costs about 50 µs a run.
/// - NFKC, which `LIKE` needs, takes time quadratic in a run of marks it reorders, up to about 0.7 µs for a scalar it
///   expands, and time that grows with the value's length for each scalar it changes.
///
/// Each weight charges the shape's bound on those, which overcharges most text that isn't ASCII and never
/// undercharges it.
enum ScanCost {
    /// One step of a search (``StringMatching/firstIndex(of:failure:in:from:to:folding:keepsLines:budget:)``): about
    /// 2.3 ns.
    static let step = 1
    /// A call matching `LIKE` on UTF-16 units, besides its segments' searches: about 30 ns.
    static let likeCall = 16

    /// - Parameters:
    ///   - skipped: How far a jump to a search's next candidate went, never negative.
    ///   - isByte: Over bytes, which `memchr` or SIMD skips at 0.02 ns a byte, rather than UTF-16 units, skipped one
    ///     at a time at about 0.4 ns each?
    /// - Returns: The jump's cost.
    @inline(__always)
    static func jump(_ skipped: Int, isByte: Bool) -> Int {
        1 + skipped >> (isByte ? 7 : 2)
    }

    /// - Parameter bytes: A field's length.
    /// - Returns: Working out whether it's ASCII, at 0.05 ns a byte.
    @inline(__always)
    static func isASCII(_ bytes: Int) -> Int { bytes >> 5 }

    /// The first pass of an `ANY` reaches 43,690 short elements of a pool's 131,072 units: about 0.5 MiB of
    /// `ARG_MAX` as 3-byte variables, after which an ASCII match past them is undetermined.
    ///
    /// - Parameter bytes: An `ANY` element's length.
    /// - Returns: Visiting it in the first pass and comparing it there if it's ASCII: about 6.5 ns short, 14.5 ns at
    ///   40 bytes.
    @inline(__always)
    static func element(_ bytes: Int) -> Int { 3 + bytes >> 3 }

    /// - Parameter bytes: The part of a value handed to Foundation.
    /// - Returns: Making its `NSString` and working out its shape, then letting the string go: 1.2 to 2.9 ns a byte,
    ///   170 ns small.
    @inline(__always)
    static func make(_ bytes: Int) -> Int { 64 + bytes + bytes >> 2 }

    /// `NSString` `==` with options, or `BEGINSWITH`: they read the value as far as the constant and the grapheme
    /// cluster where it stops matching, which is at most the shape's longest run past it. 150 to 362 ns, and up to
    /// 10 ns a scalar of a run of marks.
    ///
    /// - Parameters:
    ///   - constant: The constant's UTF-8 length.
    ///   - shape: The part of the value handed to Foundation.
    /// - Returns: The comparison's cost.
    @inline(__always)
    static func anchored(constant: Int, _ shape: ValueShape) -> Int {
        128 + 4 * (constant + shape.longestRun)
    }

    /// Foundation's `CONTAINS`: 2.5 to 5 ns a byte, and up to 23 ns a scalar that isn't ASCII. With `[d]`, up to
    /// 0.8 ns more per square of each run's length.
    ///
    /// - Parameters:
    ///   - bytes: The part of a value handed to Foundation.
    ///   - shape: Its shape.
    ///   - diacritics: Is the search diacritic-insensitive?
    /// - Returns: The search's cost.
    @inline(__always)
    static func contains(_ bytes: Int, _ shape: ValueShape, diacritics: Bool) -> Int {
        192 + 2 * bytes + 6 * shape.scalars + (diacritics ? shape.runSquares >> 1 : 0)
    }

    /// Foundation's `ENDSWITH`, anchored and backwards: up to 16 ns a byte on hostile text, up to 16 ns more per
    /// square of each run's first 64 scalars, and the same quadratic term as ``contains(_:_:diacritics:)`` with `[d]`.
    ///
    /// - Parameters:
    ///   - bytes: The part of a value handed to Foundation.
    ///   - shape: Its shape.
    ///   - diacritics: Is the search diacritic-insensitive?
    /// - Returns: The search's cost.
    @inline(__always)
    static func endsWith(_ bytes: Int, _ shape: ValueShape, diacritics: Bool) -> Int {
        192 + 10 * bytes + 8 * shape.cappedRunSquares + (diacritics ? shape.runSquares >> 1 : 0)
    }

    /// A value's `LIKE` units, NFKC and folded: 4 to 35 ns a byte on most text. Up to 0.7 µs a scalar NFKC expands
    /// (U+FDFA is eighteen), 0.04 ns more per byte of the value for each scalar it changes, and 0.33 ns per square
    /// of a run of marks it reorders.
    ///
    /// - Parameters:
    ///   - bytes: The value, which isn't past Foundation's window.
    ///   - shape: Its shape.
    /// - Returns: Making its units.
    @inline(__always)
    static func likeUnits(_ bytes: Int, _ shape: ValueShape) -> Int {
        128 + 8 * bytes + 256 * shape.scalars + (bytes * shape.scalars) >> 5 + shape.runSquares >> 1
    }
}


// MARK: - Value shapes
/// What the part of a value handed to Foundation is made of, beyond its length, which Foundation's costs grow with
/// (``ScanCost``): its scalars that aren't ASCII, and its runs of them, which bound its runs of combining marks and
/// its grapheme clusters. A run ends at ASCII, and at a CJK ideograph from U+4000 to U+9FFF (UTF-8 led by 0xE4 to
/// 0xE9), which is a starter that nothing before it combines with and NFKC leaves alone. Worked out from its UTF-8
/// while its `NSString` is made, which ``ScanCost/make(_:)`` pays for, and kept with it.
struct ValueShape: Equatable, Sendable {
    /// Its scalars that aren't ASCII.
    private(set) var scalars = 0
    /// Its longest run of them.
    private(set) var longestRun = 0
    /// The sum of each run's length squared.
    private(set) var runSquares = 0
    /// The sum of each run's length, at most ``bufferedRun``, squared.
    private(set) var cappedRunSquares = 0
    /// The most of a run of marks Foundation's backwards search reorders at once.
    static let bufferedRun = 64

    /// An ASCII value's shape.
    init() {}

    /// - Parameter bytes: A value's UTF-8, cut where a scalar starts.
    init(of bytes: UnsafeBufferPointer<UInt8>) {
        var run = 0
        for byte in bytes where byte < 0x80 || byte >= 0xC0 {
            guard byte >= 0xC0 else {
                end(&run)
                continue
            }
            scalars &+= 1
            guard byte &- 0xE4 > 5 else {
                end(&run)
                continue
            }
            run &+= 1
            longestRun = Swift.max(longestRun, run)
        }
        end(&run)
    }

    /// Count a run that's ended.
    ///
    /// - Parameter run: Its length, set to 0.
    @inline(__always)
    private mutating func end(_ run: inout Int) {
        guard run > 0 else { return }
        let capped = Swift.min(run, Self.bufferedRun)
        runSquares &+= run &* run
        cappedRunSquares &+= capped &* capped
        run = 0
    }
}
