//
//  TextBrackets.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/25/26.
//

import Foundation


// MARK: - Brackets
/// Matching brackets in text that has no outline, such as a script: `{}`, `[]` and `()`, by counting how deep each
/// bracket of the same kind nests, as far as a limit. A JSON text's brackets come from its ``JSONOutline`` instead,
/// which skips the ones in strings.
public enum TextBrackets {
    /// Each bracket, the bracket that matches it, and whether the match is after it.
    private static let pairs: [UInt16: (match: UInt16, forward: Bool)] = [
        0x7B: (0x7D, true), 0x5B: (0x5D, true), 0x28: (0x29, true),
        0x7D: (0x7B, false), 0x5D: (0x5B, false), 0x29: (0x28, false)
    ]

    /// How far a match is looked for, in UTF-16 units, so the cost of moving the cursor stays small.
    public static let limit = 20_000

    /// The bracket matching one.
    ///
    /// - Parameters:
    ///   - offset: Where a bracket is.
    ///   - text: The text.
    ///   - limit: How far to look, in UTF-16 units.
    /// - Returns: Where the bracket that matches it is, or `nil` when there's no bracket there or no match in reach.
    public static func match(at offset: Int, in text: NSString, limit: Int = limit) -> Int? {
        guard offset >= 0, offset < text.length, let pair = pairs[text.character(at: offset)] else { return nil }
        let bracket = text.character(at: offset)
        let step = pair.forward ? 1 : -1
        let end = pair.forward ? min(text.length, offset + limit + 1) : max(-1, offset - limit - 1)
        var depth = 0
        for index in stride(from: offset, to: end, by: step) {
            let unit = text.character(at: index)
            if unit == bracket {
                depth += 1
            } else if unit == pair.match {
                depth -= 1
                if depth == 0 { return index }
            }
        }
        return nil
    }
}
