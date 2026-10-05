//
//  String+Counted.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/5/26.
//

import Foundation


// MARK: - Counted nouns
extension String {
    /// A count of things for `macmonitor`'s messages, singular for one. No thousands separators, so the text doesn't
    /// change with the locale `sudo` runs in.
    ///
    /// - Parameters:
    ///   - count: How many.
    ///   - noun: What they are, singular: an "s" makes it plural.
    /// - Returns: Such as "1 mute" or "1000 events".
    static func counted<Count: BinaryInteger>(_ count: Count, _ noun: String) -> String {
        "\(count) \(noun)\(count == 1 ? "" : "s")"
    }
}
