//
//  TextLines.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Lines
/// Where each line of a text starts, so the line an offset is on is found by binary search instead of by counting line
/// feeds. Offsets are UTF-16 units, as `NSString` and `NSTextView` count them. A line ends at a line feed.
public struct TextLines: Equatable {
    /// Where each line starts: 0, then just after each line feed. A final line feed starts an empty last line.
    public let starts: [Int]
    /// The text's length.
    public let length: Int

    /// - Parameter text: The text.
    public init(_ text: String) {
        var starts = [0]
        var offset = 0
        for unit in text.utf16 {
            offset += 1
            if unit == 0x0A { starts.append(offset) }
        }
        self.init(starts: starts, length: offset)
    }

    /// - Parameters:
    ///   - starts: Where each line starts, from 0, in order.
    ///   - length: The text's length.
    init(starts: [Int], length: Int) {
        self.starts = starts
        self.length = length
    }

    /// How many lines there are, an empty last line after a final line feed included.
    public var count: Int { starts.count }

    /// The line an offset is on.
    ///
    /// - Parameter offset: An offset in the text. One before the start is on the first line, one past the end on the
    ///   last.
    /// - Returns: The line, from 0.
    public func line(at offset: Int) -> Int {
        var low = 0, high = starts.count - 1
        while low < high {
            let middle = (low + high + 1) / 2
            if starts[middle] <= offset { low = middle } else { high = middle - 1 }
        }
        return low
    }

    /// A line's text.
    ///
    /// - Parameter line: A line, from 0. One out of range is the first or the last.
    /// - Returns: The line's range, without its line feed.
    public func range(of line: Int) -> NSRange {
        let line = min(max(line, 0), starts.count - 1)
        let end = line + 1 < starts.count ? starts[line + 1] - 1 : length
        return NSRange(location: starts[line], length: end - starts[line])
    }
}
