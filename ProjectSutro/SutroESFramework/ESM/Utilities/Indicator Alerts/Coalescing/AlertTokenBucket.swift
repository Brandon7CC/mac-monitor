//
//  AlertTokenBucket.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Tokens
/// A token bucket on an injected clock: it starts full, and one token comes back every ``every`` seconds, up to
/// ``capacity``. Each notification takes one.
struct AlertTokenBucket: Sendable {
    /// The most tokens it holds.
    let capacity: Double
    /// Seconds for one token to come back.
    let every: TimeInterval
    /// The tokens now, as of ``last``.
    private(set) var tokens: Double
    /// When the tokens were last counted, or `nil` before the first take.
    private var last: TimeInterval?

    /// - Parameters:
    ///   - capacity: The most tokens it holds, and what it starts with.
    ///   - every: Seconds for one token to come back.
    init(capacity: Double, every: TimeInterval) {
        (self.capacity, self.every, tokens) = (capacity, every, capacity)
    }

    /// Count the tokens that came back since the last count.
    ///
    /// - Parameter now: The clock now.
    private mutating func refill(_ now: TimeInterval) {
        if let last { tokens = min(capacity, tokens + max(0, now - last) / every) }
        last = now
    }

    /// Take a token, if at least `need` are there.
    ///
    /// - Parameters:
    ///   - now: The clock now.
    ///   - need: The tokens that must be there. One is taken.
    /// - Returns: Was one taken?
    mutating func take(now: TimeInterval, need: Double = 1) -> Bool {
        refill(now)
        guard tokens >= need else { return false }
        tokens -= 1
        return true
    }

    /// - Parameter now: The clock now.
    /// - Returns: When the next token is there: `now` when one is.
    mutating func nextToken(now: TimeInterval) -> TimeInterval {
        refill(now)
        return tokens >= 1 ? now : now + (1 - tokens) * every
    }
}
