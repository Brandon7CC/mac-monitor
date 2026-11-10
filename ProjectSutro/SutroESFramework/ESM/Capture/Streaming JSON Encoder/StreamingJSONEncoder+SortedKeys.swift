//
//  StreamingJSONEncoder+SortedKeys.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Key order
extension StreamingJSONEncoder {
    /// The order `.sortedKeys` writes an object's members in, which depends on the Mac's `JSONEncoder`.
    enum KeyOrder {
        /// By the keys' UTF-8 bytes: macOS 27's.
        case bytes
        /// As `NSString` compares them in the system locale, numeric and case-insensitive (`_a` before `A`, `a_b`
        /// before `a1`, `a2` before `a10`): macOS 13's (``KeyRanks/precedes(_:_:)``).
        ///
        /// That `JSONEncoder` also writes a floating-point number with 17 significant digits
        /// (`0.10000000000000001`), so a sorted value with one is left to it. It drops a U+FEFF that starts a string,
        /// which this keeps.
        case localized
    }

    /// The order this Mac's `JSONEncoder` sorts keys in, found by sorting a probe with it. `nil` if it's neither
    /// order, or sorts by bytes but doesn't write `0.1` as `0.1`: sorted values are then left to `JSONEncoder`.
    static let jsonEncoderKeyOrder: KeyOrder? = {
        let keys = ["a_b", "a1", "a10", "a2", "aB", "ab", "A", "_a", "a.b", "a-b", "é", "e", "z", "Z9", "pid",
                    "pid_version", "pidversion", "sha1", "sha256", "sha2", "p1", "p10", "p2", "p02", "1", "10", "2",
                    "02", "a b", "A_b", "a_B", "ss", "x86_64", "arm64", "arm64e", "cdhash", "cd_hash", "uid", "UID",
                    "a", "aa", "a_", "a__b", "a0", "a00", "a01", "a1b", "a1_b", "a_1", "x_y", "xy", "x-y", "x.y"]
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let probe = Dictionary(uniqueKeysWithValues: keys.map { ($0, 0) })
        guard let json = try? encoder.encode(probe), let number = try? encoder.encode([0.1]) else { return nil }
        /// The probe as it's written with its keys in an order.
        func written(_ keys: [String]) -> Data {
            Data(("{" + keys.map { "\"\($0)\":0" }.joined(separator: ",") + "}").utf8)
        }
        if json == written(keys.sorted()) { return number == Data("[0.1]".utf8) ? .bytes : nil }
        return json == written(keys.sorted(by: KeyRanks.precedes)) ? .localized : nil
    }()

    /// Can sorted values be written here as this Mac's `JSONEncoder` writes them?
    static var sortsKeysAsJSONEncoderDoes: Bool { jsonEncoderKeyOrder != nil }
}


// MARK: - Sorting members
extension StreamingJSONEncoder {
    /// Put the closing object's members in key order (``State/keyOrder``), as `.sortedKeys` orders them, and forget
    /// them. An object with a key twice is left to `JSONEncoder`, which keeps the last value.
    ///
    /// Its nested objects closed first, so each moves already sorted. The object keeps its length: the same members
    /// and commas, in another order.
    ///
    /// - Parameter first: The object's first member in ``State/members``.
    func sortMembers(from first: Int) {
        defer { state.pointee.members.removeSubrange(first...) }
        let members = state.pointee.members[first...]
        guard members.count > 1 else { return }
        let sorted: [Int]?
        switch state.pointee.keyOrder {
        case .bytes:
            sorted = Self.order(members.indices) { members[$0].key < members[$1].key }
        case .localized:
            if let ranks = state.pointee.keyRanks.ranks(of: members) {
                sorted = Self.order(members.indices) { ranks[$0 - first] < ranks[$1 - first] }
            } else {
                sorted = Self.order(members.indices) { KeyRanks.precedes(members[$0].key, members[$1].key) }
            }
        }
        guard let order = sorted else { return }
        guard zip(order, order.dropFirst()).allSatisfy({ members[$0].key != members[$1].key }) else {
            state.pointee.isUnstreamable = true
            return
        }
        move(members, into: order)
    }

    /// Put members in an order.
    ///
    /// - Parameters:
    ///   - indices: The members' places in ``State/members``.
    ///   - precedes: Does the member at a place come before the one at another?
    /// - Returns: The places in order, or `nil` if they're in order already.
    private static func order(_ indices: Range<Int>, precedes: (Int, Int) -> Bool) -> [Int]? {
        if zip(indices, indices.dropFirst()).allSatisfy(precedes) { return nil }
        return indices.sorted(by: precedes)
    }

    /// Rewrite the closing object with its members in an order.
    ///
    /// - Parameters:
    ///   - members: The object's members, as they were written.
    ///   - order: Their places in ``State/members``, in the order to write them.
    private func move(_ members: ArraySlice<Member>, into order: [Int]) {
        let start = members[members.startIndex].start, end = state.pointee.count, length = end - start
        if length > state.pointee.scratchCapacity {
            state.pointee.scratch.deallocate()
            state.pointee.scratchCapacity = max(length, state.pointee.scratchCapacity * 2)
            state.pointee.scratch = .allocate(capacity: state.pointee.scratchCapacity)
        }
        let scratch = state.pointee.scratch
        scratch.update(from: state.pointee.base + start, count: length)
        var out = state.pointee.base + start
        for (position, index) in order.enumerated() {
            if position > 0 { out.pointee = UInt8(ascii: ","); out += 1 }
            /// A member ends at the next one's comma, or at the end of the object.
            let from = members[index].start, to = index + 1 < members.endIndex ? members[index + 1].start - 1 : end
            out.update(from: scratch + (from - start), count: to - from)
            out += to - from
        }
    }
}
