//
//  SequenceChains+Chain.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Keys and chains
extension SequenceChains {
    /// Where a chain or early step is kept: its step, the variant in the bits above it, and its key.
    struct Key: Hashable {
        /// Its key.
        let hash: SequenceHash
        /// The step a chain waits for, 0 for an unordered one, or an early event matched, and its variant times 8.
        let step: UInt8

        /// - Parameters:
        ///   - hash: The key.
        ///   - step: The step, under 8.
        ///   - variant: Which of the step's ``SequenceChains/variants``.
        init(hash: SequenceHash, step: Int, variant: Int = 0) {
            self.hash = hash
            self.step = UInt8(step | variant << 3)
        }
    }

    /// One chain, or an early step, whose ``first`` and ``last`` are its event's time: 96 bytes.
    struct Chain {
        /// Which change of its store made it as it is, which its place in line must name.
        var stamp: UInt64 = 0
        /// When its first step matched.
        var first: Double
        /// When its latest step matched.
        var last: Double
        /// Its `by` values' hash.
        let by: SequenceHash
        /// The values later steps join to, by slot, while a later step still needs them.
        var slots: ContiguousArray<SequenceHash>?
        /// An unordered chain's latest time for each step, in seconds after ``first``: minus infinity for none.
        var times = SIMD8<Float>(repeating: -.infinity)
        /// Which of the chain's events matched each step last, by ``eventCount`` when it came, so one event that
        /// matched several steps counts once.
        var events = SIMD8<UInt8>(repeating: 0)
        /// How many events matched an unordered chain's steps, modulo 256.
        var eventCount: UInt8 = 0
        /// The event an ordered chain's latest step, or an early step, came from, by the table's count of the events
        /// it advanced, so a chain never takes two steps from one event.
        var source: UInt32 = 0

        /// When a waiting ordered chain stopped being the one an event advances: once a chain that started later came
        /// to wait under its key, or it came after one had, in time order. Plus infinity until then. Kept as an
        /// offset from ``first`` in the first lane of ``times``, which only an unordered chain uses, so a chain stays
        /// 96 bytes: a waiting chain's is set as it's kept, and it's at most its window and the lateness past
        /// ``first``.
        var until: Double {
            get { first + Double(times[0]) }
            set { times[0] = Float(newValue - first) }
        }

        /// When the latest-started chain that took an early step started: minus infinity until one does. A chain that
        /// started later, come late, may take it too, as in time order it would have been the one to. Kept as an
        /// offset from ``first`` in the second lane of ``times``, which only an unordered chain uses.
        var takenBy: Double {
            get { first + Double(times[1]) }
            set { times[1] = Float(newValue - first) }
        }
    }
}
