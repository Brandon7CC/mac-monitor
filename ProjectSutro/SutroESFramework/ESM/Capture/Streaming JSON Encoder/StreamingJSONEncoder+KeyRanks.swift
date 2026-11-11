//
//  StreamingJSONEncoder+KeyRanks.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/9/26.
//

import Foundation


// MARK: - Key ranks
extension StreamingJSONEncoder {
    /// Ranks keys in the order macOS 13's `JSONEncoder` sorts them (``KeyOrder/localized``), so an object's members
    /// are put in that order by comparing integers.
    ///
    /// That order is `NSString`'s (``precedes(_:_:)``), and comparing two keys that way costs far more than comparing
    /// their bytes: an event's record has some 150 members, so sorting them by it would cost more than writing the
    /// record. A record's keys are the telemetry schema's, a few hundred in all, so each key is compared only when
    /// it's first seen, to find its place among those seen before. After that an object's sort is a table lookup for
    /// each member.
    ///
    /// Holds at most ``limit`` keys, so keys that aren't the schema's can't grow it without bound.
    struct KeyRanks {
        /// The most keys ranked.
        static let limit = 4_096
        /// The keys seen so far, in order.
        private var keys: [String] = []
        /// Each key's place in ``keys``.
        private var rankOfKey: [String: Int] = [:]

        /// Does a key come before another, as macOS 13's `JSONEncoder` sorts them with `.sortedKeys`?
        ///
        /// - Parameters:
        ///   - key: A key.
        ///   - other: Another key.
        /// - Returns: `true` if `key` is written first.
        static func precedes(_ key: String, _ other: String) -> Bool {
            key.compare(other, options: [.numeric, .caseInsensitive, .widthInsensitive, .forcedOrdering],
                        range: key.startIndex..<key.endIndex, locale: NSLocale.system) == .orderedAscending
        }

        /// Rank an object's members.
        ///
        /// - Parameter members: The members.
        /// - Returns: Each member's rank, lower for the key written first and equal for equal keys, good until the
        ///   next call. `nil` if their keys don't all fit: compare them with ``precedes(_:_:)`` instead.
        mutating func ranks(of members: ArraySlice<Member>) -> [Int]? {
            var ranks: [Int] = []
            ranks.reserveCapacity(members.count)
            for member in members {
                guard let rank = rankOfKey[member.key] else { break }
                ranks.append(rank)
            }
            if ranks.count == members.count { return ranks }
            guard add(members) else { return nil }
            return members.map { rankOfKey[$0.key] ?? 0 }
        }

        /// Give the members' keys that have no rank yet their places, which moves the ranks after them.
        ///
        /// - Parameter members: The members.
        /// - Returns: `false`, changing nothing, if the keys don't all fit.
        private mutating func add(_ members: ArraySlice<Member>) -> Bool {
            var new: Set<String> = []
            for member in members where rankOfKey[member.key] == nil { new.insert(member.key) }
            guard keys.count + new.count <= Self.limit else { return false }
            for key in new {
                var low = 0, high = keys.count
                while low < high {
                    let middle = (low + high) / 2
                    if Self.precedes(keys[middle], key) { low = middle + 1 } else { high = middle }
                }
                keys.insert(key, at: low)
            }
            for (rank, key) in keys.enumerated() { rankOfKey[key] = rank }
            return true
        }
    }
}
