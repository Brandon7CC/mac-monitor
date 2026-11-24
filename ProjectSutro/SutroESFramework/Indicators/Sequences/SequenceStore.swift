//
//  SequenceStore.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Stores
/// Chains, or early steps, by key, and the line they're dropped from, oldest change first (``SequenceChains``). A
/// store holds at most the capacity it's given: past it, it drops a dead entry near the front of the line, or else
/// the front, which changed longest ago, and counts it (``evictions``).
///
/// **Threading:** none of its own. Its table holds it behind a lock.
struct SequenceStore {
    typealias Key = SequenceChains.Key
    typealias Chain = SequenceChains.Chain

    /// When an entry can go: once no event a lane may still hand over can join it or take it.
    struct Mortality {
        /// What an entry's life runs from.
        enum Kind {
            /// An early step's time: steps from before it can still come until the horizon passes it.
            case early
            /// An ordered chain's first step: its window runs from it.
            case ordered
            /// An unordered chain's latest step: a window around a later event can still hold it.
            case unordered
        }

        /// The earliest time an event a lane may still hand over can have: the latest less the lateness.
        let horizon: Double
        /// The sequence's window.
        let within: Double
        /// What an entry's life runs from.
        let kind: Kind

        /// - Parameter chain: An entry.
        /// - Returns: Can it go?
        func isDead(_ chain: Chain) -> Bool {
            switch kind {
            case .early: chain.first < horizon
            case .ordered: horizon - chain.first > within
            case .unordered: horizon - chain.last > within
            }
        }
    }

    /// An entry's place in line, which it lost once a later change restamped it.
    struct Entry {
        /// Where the entry is.
        let key: Key
        /// The change it was put in line by.
        let stamp: UInt64
    }

    /// How many entries past the line's front ``makeRoom(capacity:_:)`` looks for a dead entry before it drops a live
    /// one.
    static let lookahead = 8

    /// The entries by key.
    private(set) var entries: [Key: Chain] = [:]
    /// How many it dropped to stay under its capacity.
    private(set) var evictions = 0
    /// Each change, oldest first from ``head``. An entry changed since is a stale entry.
    private var order: [Entry] = []
    /// The first entry still in line.
    private var head = 0
    /// The last change's stamp.
    private var stamp: UInt64 = 0

    /// How many entries it holds.
    var count: Int { entries.count }

    /// Does it hold none?
    var isEmpty: Bool { entries.isEmpty }

    /// How long its line is, the consumed and stale entries included: what ``compact(capacity:)`` keeps near its
    /// count.
    var lineLength: Int { order.count }

    /// Forget every entry, keeping the count of evictions.
    mutating func forget() {
        let evictions = evictions
        self = SequenceStore()
        self.evictions = evictions
    }

    /// The entry at a key, unless it's dead, which is dropped.
    ///
    /// - Parameters:
    ///   - key: The key.
    ///   - mortality: When an entry can go.
    /// - Returns: It, or `nil`.
    mutating func live(at key: Key, _ mortality: Mortality) -> Chain? {
        guard let chain = entries[key] else { return nil }
        guard mortality.isDead(chain) else { return chain }
        entries[key] = nil
        return nil
    }

    /// The entry at a key, dead or alive.
    ///
    /// - Parameter key: The key.
    /// - Returns: It, or `nil`.
    subscript(key: Key) -> Chain? { entries[key] }

    /// Change the entry at a key in place, keeping its place in line.
    ///
    /// - Parameters:
    ///   - key: The key.
    ///   - change: What to change.
    mutating func update(_ key: Key, _ change: (inout Chain) -> Void) {
        guard var chain = entries[key] else { return }
        change(&chain)
        entries[key] = chain
    }

    /// Drop the entry at a key, as a chain that advances or completes is.
    ///
    /// - Parameter key: The key.
    mutating func remove(_ key: Key) {
        entries[key] = nil
    }

    /// Keep an entry, last in line, making room for a new one first.
    ///
    /// - Parameters:
    ///   - chain: The entry.
    ///   - key: Its key.
    ///   - capacity: The most entries to hold.
    ///   - mortality: When an entry can go.
    mutating func keep(_ chain: Chain, under key: Key, capacity: Int, _ mortality: Mortality) {
        var chain = chain
        stamp &+= 1
        chain.stamp = stamp
        if entries[key] == nil { makeRoom(capacity: capacity, mortality) }
        entries[key] = chain
        order.append(Entry(key: key, stamp: stamp))
        compact(capacity: capacity)
    }

    /// Is an entry still a chain's place in line?
    ///
    /// - Parameter entry: The entry.
    /// - Returns: Its chain, or `nil` for a stale entry.
    private func live(_ entry: Entry) -> Chain? {
        entries[entry.key].flatMap { $0.stamp == entry.stamp ? $0 : nil }
    }

    /// Drop stale and dead entries from the front of the line. At capacity, drop a dead entry a few further back if
    /// there is one, as an ordered chain that advanced keeps its first step's window, and otherwise the one at the
    /// front, which changed longest ago, counting it.
    ///
    /// - Parameters:
    ///   - capacity: The most entries to hold.
    ///   - mortality: When an entry can go.
    private mutating func makeRoom(capacity: Int, _ mortality: Mortality) {
        while head < order.count {
            guard let chain = live(order[head]) else {
                head += 1
                continue
            }
            if mortality.isDead(chain) {
                entries[order[head].key] = nil
            } else if entries.count >= capacity {
                if dropDead(behind: head, mortality) { return }
                entries[order[head].key] = nil
                evictions += 1
            } else {
                return
            }
            head += 1
        }
    }

    /// Drop a dead entry among the few behind the front of the line.
    ///
    /// - Parameters:
    ///   - front: The front entry.
    ///   - mortality: When an entry can go.
    /// - Returns: Did it drop one?
    private mutating func dropDead(behind front: Int, _ mortality: Mortality) -> Bool {
        for index in (front + 1)..<min(order.count, front + 1 + Self.lookahead) {
            guard let chain = live(order[index]), mortality.isDead(chain) else { continue }
            entries[order[index].key] = nil
            return true
        }
        return false
    }

    /// Rebuild the line from its live entries once its consumed and stale entries outnumber its entries, so it stays
    /// within about twice its count, plus a little slack that's smaller for a small store, and give back the
    /// dictionary's room once a burst is gone. Each rebuild follows at least as many changes as it walks, so a change
    /// costs a constant amount on average.
    ///
    /// - Parameter capacity: The most entries it holds.
    private mutating func compact(capacity: Int) {
        guard order.count > 2 * entries.count + min(64, capacity) else { return }
        order = order[head...].filter { live($0) != nil }
        head = 0
        guard entries.capacity > 1_024, entries.count * 4 < entries.capacity else { return }
        var smaller = [Key: Chain](minimumCapacity: entries.count * 2)
        for (key, chain) in entries { smaller[key] = chain }
        entries = smaller
    }
}
