//
//  SequenceHash.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Sequence hashes
/// 128 bits that stand for the values a sequence ties its steps by: a step's `by` values, or one value a later step
/// joins to. A chain keeps these rather than the strings, so it holds a fixed number of bytes whatever the values are.
///
/// Two values are one hash exactly when `==` without options would call them equal: strings by their bytes, numbers
/// by value, Booleans as 1 and 0. Each half is SipHash, as `Hasher` computes it, with the process's random seed, so
/// an event's author can't choose values that collide.
struct SequenceHash: Hashable, Sendable {
    /// The first 64 bits.
    let low: UInt64
    /// The second 64 bits.
    let high: UInt64

    /// - Parameter hasher: Only the low half: the high half is the same hash with another seed, and adds nothing to a
    ///   `Dictionary`'s.
    func hash(into hasher: inout Hasher) {
        hasher.combine(low)
    }
}


// MARK: - Hashing values
/// Hashes values, in order, into a ``SequenceHash``.
struct SequenceHasher {
    /// The low half's.
    private var low = Hasher()
    /// The high half's.
    private var high = Hasher()

    /// A hasher with nothing in it, each half seeded apart.
    init() {
        low.combine(UInt8(0x4C))
        high.combine(UInt8(0x48))
    }

    /// Add a value.
    ///
    /// - Parameter value: A field's value on an event.
    /// - Returns: `false` for a missing value, which ties nothing, and nothing was added.
    mutating func combine(_ value: IndicatorValue) -> Bool {
        switch value {
        case .null:
            return false
        case .string(let string):
            add(UInt8(1))
            add(bytes: string)
        case .number(let number, _):
            add(UInt8(2))
            /// `-0` is `0`, as `==` has it. Numbers are finite: the compiler and the record allow nothing else.
            add(number == 0 ? 0 : number.bitPattern)
        case .strings(let strings):
            add(UInt8(3))
            add(UInt64(strings.count))
            for string in strings { add(bytes: string[...]) }
        }
        return true
    }

    /// Add another hash.
    ///
    /// - Parameter hash: The hash.
    mutating func combine(_ hash: SequenceHash) {
        add(hash.low)
        add(hash.high)
    }

    /// - Returns: The hash of everything added.
    func finalize() -> SequenceHash {
        SequenceHash(low: UInt64(bitPattern: Int64(low.finalize())), high: UInt64(bitPattern: Int64(high.finalize())))
    }

    /// - Parameter value: A value to add to both halves.
    private mutating func add<T: Hashable>(_ value: T) {
        low.combine(value)
        high.combine(value)
    }

    /// Add a string's length and bytes, so two strings never run together.
    ///
    /// - Parameter string: The string.
    private mutating func add(bytes string: Substring) {
        var string = string
        string.withUTF8 { bytes in
            add(UInt64(bytes.count))
            low.combine(bytes: UnsafeRawBufferPointer(bytes))
            high.combine(bytes: UnsafeRawBufferPointer(bytes))
        }
    }
}
