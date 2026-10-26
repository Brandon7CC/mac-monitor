//
//  StreamingJSONEncoder+SortedKeys.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 10/26/26.
//

import Foundation


// MARK: - Sorted keys
extension StreamingJSONEncoder {
    /// Does this Mac's `JSONEncoder` sort keys by their UTF-8 bytes, as ``sortMembers(from:)`` does? It does on
    /// macOS 27. macOS 13's compares them as `NSString` does, localized, numeric and case-insensitive (`_a` before `A`,
    /// `a_b` before `a1`, `a2` before `a10`), so its records are left to `JSONEncoder` there to stay what it writes.
    static let sortsKeysAsJSONEncoderDoes: Bool = {
        let keys = ["a_b", "a1", "a10", "a2", "aB", "ab", "A", "_a", "a.b", "a-b", "é", "e", "z", "Z9"]
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let probe = Dictionary(uniqueKeysWithValues: keys.map { ($0, 0) })
        guard let json = try? encoder.encode(probe) else { return false }
        return json == Data(("{" + keys.sorted().map { "\"\($0)\":0" }.joined(separator: ",") + "}").utf8)
    }()
    
    /// Put the closing object's members in key order, by their keys' UTF-8 bytes as `.sortedKeys` orders them, and
    /// forget them. An object with a key twice is left to `JSONEncoder`, which keeps the last value.
    ///
    /// Its nested objects closed first, so each moves already sorted. The object keeps its length: the same members
    /// and commas, in another order.
    ///
    /// - Parameter first: The object's first member in ``State/members``.
    func sortMembers(from first: Int) {
        defer { state.pointee.members.removeSubrange(first...) }
        let members = state.pointee.members[first...]
        guard members.count > 1 else { return }
        if zip(members, members.dropFirst()).allSatisfy({ $0.key < $1.key }) { return }
        let order = members.indices.sorted { members[$0].key < members[$1].key }
        guard zip(order, order.dropFirst()).allSatisfy({ members[$0].key != members[$1].key }) else {
            state.pointee.isUnstreamable = true
            return
        }
        let start = members[first].start, end = state.pointee.count, length = end - start
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
