//
//  TextFolds.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Folds
/// The parts of a text a view hides behind placeholders, such as folded JSON objects, and how offsets in the text it
/// shows map to the text's own. A fold inside another is hidden with it, so only the outermost are shown. Offsets are
/// UTF-16 units.
public struct TextFolds: Equatable {
    /// One part hidden.
    public struct Fold: Equatable {
        /// What it hides, in the text.
        public let range: NSRange
        /// What's shown instead.
        public let placeholder: String

        /// - Parameters:
        ///   - range: What it hides, in the text.
        ///   - placeholder: What's shown instead.
        public init(range: NSRange, placeholder: String) {
            self.range = range
            self.placeholder = placeholder
        }

        /// The placeholder's length.
        var shownLength: Int { placeholder.utf16.count }
    }

    /// One piece of the text shown: some of the text, or a fold's placeholder.
    public enum Piece: Equatable {
        /// The text in a range of it.
        case text(NSRange)
        /// A shown fold's placeholder, by its place in ``TextFolds/shown``.
        case fold(Int)
    }

    /// The folds shown, the outermost, in order.
    public let shown: [Fold]
    /// Where each shown fold's placeholder starts in the text shown.
    private let starts: [Int]

    /// No folds.
    public static let none = TextFolds([])

    /// - Parameter folds: Folds in any order. One inside another, or one overlapping one before it, isn't shown, nor
    ///   is an empty one.
    public init(_ folds: [Fold]) {
        let sorted = folds.filter { $0.range.length > 0 }.sorted {
            $0.range.location != $1.range.location ? $0.range.location < $1.range.location
                : $0.range.length > $1.range.length
        }
        var kept: [Fold] = []
        for fold in sorted where kept.last.map({ fold.range.location >= NSMaxRange($0.range) }) ?? true {
            kept.append(fold)
        }
        var removed = 0
        starts = kept.map { fold in
            defer { removed += fold.range.length - fold.shownLength }
            return fold.range.location - removed
        }
        shown = kept
    }

    // MARK: Mapping
    /// Where an offset in the text is in the text shown.
    ///
    /// - Parameter offset: An offset in the text.
    /// - Returns: The offset shown. One a fold hides is at its placeholder's start.
    public func shown(_ offset: Int) -> Int {
        guard let index = last(shown.lazy.map(\.range.location), atOrBefore: offset) else { return offset }
        let fold = shown[index]
        guard offset >= NSMaxRange(fold.range) else { return starts[index] }
        return starts[index] + fold.shownLength + offset - NSMaxRange(fold.range)
    }

    /// Where an offset in the text shown is in the text.
    ///
    /// - Parameter offset: An offset in the text shown.
    /// - Returns: The offset in the text. One in a placeholder is at its fold's start.
    public func original(_ offset: Int) -> Int {
        guard let index = last(starts, atOrBefore: offset) else { return offset }
        let fold = shown[index], end = starts[index] + fold.shownLength
        return offset < end ? fold.range.location : NSMaxRange(fold.range) + offset - end
    }

    /// - Parameter range: A range of the text.
    /// - Returns: The range shown, from where its start is shown to where its end is.
    public func shown(_ range: NSRange) -> NSRange {
        let start = shown(range.location)
        return NSRange(location: start, length: shown(NSMaxRange(range)) - start)
    }

    /// - Parameter range: A range of the text shown.
    /// - Returns: The range of the text, from its start's offset to its end's, so a placeholder's end takes in all
    ///   its fold hides.
    public func original(_ range: NSRange) -> NSRange {
        let start = original(range.location)
        return NSRange(location: start, length: max(original(NSMaxRange(range)) - start, 0))
    }

    /// - Parameter offset: An offset in the text shown.
    /// - Returns: The shown fold whose placeholder holds it, by its place in ``shown``.
    public func fold(atShown offset: Int) -> Int? {
        guard let index = last(starts, atOrBefore: offset), offset < starts[index] + shown[index].shownLength else {
            return nil
        }
        return index
    }

    /// - Parameter offset: An offset in the text.
    /// - Returns: The shown fold that hides it, by its place in ``shown``. A fold hides its range from its start.
    public func fold(hiding offset: Int) -> Int? {
        guard let index = last(shown.lazy.map(\.range.location), atOrBefore: offset),
              offset < NSMaxRange(shown[index].range) else { return nil }
        return index
    }

    // MARK: Pieces
    /// What a range of the text shows, in order: its text between the folds inside it, and their placeholders.
    ///
    /// - Parameter range: A range of the text that no shown fold crosses the edge of.
    /// - Returns: The pieces. Empty runs of text are left out.
    public func pieces(of range: NSRange) -> [Piece] {
        var pieces: [Piece] = []
        var location = range.location
        /// The first fold that starts in the range. The folds are apart and in order.
        var index = last(shown.lazy.map(\.range.location), atOrBefore: range.location - 1).map { $0 + 1 } ?? 0
        while index < shown.count, NSMaxRange(shown[index].range) <= NSMaxRange(range) {
            let fold = shown[index].range
            if fold.location > location {
                pieces.append(.text(NSRange(location: location, length: fold.location - location)))
            }
            pieces.append(.fold(index))
            location = NSMaxRange(fold)
            index += 1
        }
        if NSMaxRange(range) > location {
            pieces.append(.text(NSRange(location: location, length: NSMaxRange(range) - location)))
        }
        return pieces
    }

    /// The last of some ascending values at or before a limit.
    ///
    /// - Parameters:
    ///   - values: Values in ascending order.
    ///   - limit: The limit.
    /// - Returns: The place of the last value no greater than it, or `nil` when the first is greater.
    private func last<C: RandomAccessCollection>(_ values: C, atOrBefore limit: Int) -> Int?
        where C.Element == Int, C.Index == Int {
        var low = values.startIndex, high = values.endIndex
        while low < high {
            let middle = (low + high) / 2
            if values[middle] <= limit { low = middle + 1 } else { high = middle }
        }
        return low > values.startIndex ? low - 1 : nil
    }
}
