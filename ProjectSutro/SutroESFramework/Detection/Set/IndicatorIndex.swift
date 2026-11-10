//
//  IndicatorIndex.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Indicator index
/// A compiled set's rules for each event type, indexed by the literals they need (``IndicatorAnchor``), so an event
/// is evaluated only against the rules it could match rather than every rule of its type in turn.
///
/// For each type it keeps the rules that need nothing it checks, as a bit mask, and for each field its rules compare,
/// four tries of their anchors (prefixes and whole values, and suffixes, each with letters folded or not) and the
/// anchors searched for anywhere, each once however many rules share it. An event's candidates are the mask and the
/// rules of every anchor its values have: one walk of each value per trie, from its start or its end, and one search
/// per distinct literal. A value that isn't ASCII, which Foundation compares, has every anchor of its field.
///
/// Its candidates always include every rule the event matches (`IndicatorIndexTests` checks them against the rules
/// themselves), and the set evaluates them in its order, so the hits are the same as evaluating every rule.
///
/// Its searches spend from the event's index pool (``ScanBudget/indexLimit``). One the pool can't pay for marks its
/// rules without finishing, as does every search after it, so running out costs only pruning, never a verdict.
///
/// **Threading:** immutable once made, in buffers of its own (``Frozen``), so lanes read it without a reference
/// count. Its owner frees it, once, in `deinit`.
struct IndicatorIndex {
    /// One event type's index.
    struct Bucket {
        /// Its fields' probes in ``IndicatorIndex/probes``.
        var probes: Int32 = 0, probeCount: Int32 = 0
        /// Its mask of the rules evaluated on every event, in ``IndicatorIndex/masks``, and its words.
        var mask: Int32 = 0, words: Int32 = 0
    }

    /// One field's anchors, for one event type.
    struct Probe {
        /// The field.
        var field: IndicatorField
        /// Its tries' roots in ``IndicatorIndex/nodes``, or -1 for none: prefixes and whole values, as written and
        /// folded, then suffixes, as written and folded.
        var prefix: Int32 = -1, foldedPrefix: Int32 = -1, suffix: Int32 = -1, foldedSuffix: Int32 = -1
        /// Its searches in ``IndicatorIndex/searches``.
        var searches: Int32 = 0, searchCount: Int32 = 0
        /// Every rule with an anchor on the field, in ``IndicatorIndex/marks``, for a value that isn't ASCII.
        var every: Int32 = 0, everyCount: Int32 = 0
    }

    /// One node of a trie.
    struct Node {
        /// Its children in ``IndicatorIndex/edgeBytes`` and ``IndicatorIndex/edgeNodes``.
        var edges: Int32 = 0, edgeCount: Int32 = 0
        /// The rules whose prefix or suffix ends here, in ``IndicatorIndex/marks``.
        var marks: Int32 = 0, markCount: Int32 = 0
        /// The rules whose whole value ends here.
        var exact: Int32 = 0, exactCount: Int32 = 0
    }

    /// A literal searched for anywhere in a value.
    struct Search {
        /// Its bytes in ``IndicatorIndex/bytes`` and its failure table in ``IndicatorIndex/failures``, which start at
        /// the same place.
        var offset: Int32 = 0, length: Int32 = 0
        /// The rules that need it, in ``IndicatorIndex/marks``.
        var marks: Int32 = 0, markCount: Int32 = 0
        /// Are the value's letters folded? Its bytes are lowered already.
        var folding = false
    }

    /// Each event type's index, by the type's number.
    let buckets: Frozen<Bucket>
    /// The fields' probes.
    let probes: Frozen<Probe>
    /// The masks of the rules evaluated on every event.
    let masks: Frozen<UInt64>
    /// The tries' nodes.
    let nodes: Frozen<Node>
    /// Each edge's byte, and the node it leads to.
    let edgeBytes: Frozen<UInt8>, edgeNodes: Frozen<Int32>
    /// The searched literals.
    let searches: Frozen<Search>
    /// Their bytes, and their failure tables.
    let bytes: Frozen<UInt8>, failures: Frozen<Int32>
    /// The rules each node, search and probe marks, by their position among their type's rules.
    let marks: Frozen<Int32>

    /// How many words an event type's candidates take.
    ///
    /// - Parameter type: The type's number, which the index has.
    /// - Returns: The words.
    @inline(__always)
    func words(forType type: Int) -> Int {
        Int(buckets.buffer[type].words)
    }

    /// Set the bits of an event's candidates: the rules of its type it could match, by their position among them.
    ///
    /// - Parameters:
    ///   - type: The event's type's number, which the index has.
    ///   - message: The event.
    ///   - values: The lane's values for this event.
    ///   - words: At least ``words(forType:)`` words, which it overwrites.
    func candidates(forType type: Int, _ message: borrowing Message, values: inout MessageValueCache,
                    into words: inout ContiguousArray<UInt64>) {
        let bucket = buckets.buffer[type]
        for word in 0..<Int(bucket.words) { words[word] = masks.buffer[Int(bucket.mask) + word] }
        for offset in 0..<Int(bucket.probeCount) {
            let probe = probes.buffer[Int(bucket.probes) + offset]
            guard case .string(let value) = values.value(of: probe.field, in: message) else { continue }
            guard values.isASCII(probe.field, value) else {
                mark(probe.every, probe.everyCount, &words)
                continue
            }
            StringMatching.withBytes(of: value) { value in
                walk(probe.prefix, value, fromEnd: false, folding: false, &words)
                walk(probe.foldedPrefix, value, fromEnd: false, folding: true, &words)
                walk(probe.suffix, value, fromEnd: true, folding: false, &words)
                walk(probe.foldedSuffix, value, fromEnd: true, folding: true, &words)
                for index in Int(probe.searches)..<Int(probe.searches + probe.searchCount) {
                    let search = searches.buffer[index]
                    if search.length == 0 || found(search, in: value, &values.scan) {
                        mark(search.marks, search.markCount, &words)
                    }
                }
            }
        }
    }

    /// Walk a value's bytes down a trie, from its start or its end, marking the rules of each node it reaches, and,
    /// when it reaches the value's other end, those of the whole values that end there.
    ///
    /// - Parameters:
    ///   - root: The trie's root, or -1 for none.
    ///   - value: The value's bytes.
    ///   - fromEnd: Walk from its end?
    ///   - folding: Fold its letters?
    ///   - words: The candidates.
    @inline(__always)
    private func walk(_ root: Int32, _ value: UnsafeBufferPointer<UInt8>, fromEnd: Bool, folding: Bool,
                      _ words: inout ContiguousArray<UInt64>) {
        guard root >= 0 else { return }
        var node = nodes.buffer[Int(root)]
        mark(node.marks, node.markCount, &words)
        let count = value.count
        for step in 0..<count {
            var byte = value[fromEnd ? count - 1 - step : step]
            if folding { byte = StringMatching.lowered(byte) }
            guard let next = child(of: node, byte) else { return }
            node = nodes.buffer[next]
            mark(node.marks, node.markCount, &words)
        }
        mark(node.exact, node.exactCount, &words)
    }

    /// - Parameters:
    ///   - node: A trie's node.
    ///   - byte: The next byte.
    /// - Returns: The child it leads to, or `nil`.
    @inline(__always)
    private func child(of node: Node, _ byte: UInt8) -> Int? {
        for edge in Int(node.edges)..<Int(node.edges + node.edgeCount) where edgeBytes.buffer[edge] == byte {
            return Int(edgeNodes.buffer[edge])
        }
        return nil
    }

    /// - Parameters:
    ///   - search: A literal, not empty.
    ///   - value: A value's bytes.
    ///   - scan: The event's budget, whose index pool the search spends from.
    /// - Returns: Whether the value has it, or `true`, which keeps its rules, when the pool ran out first.
    @inline(__always)
    private func found(_ search: Search, in value: UnsafeBufferPointer<UInt8>, _ scan: inout ScanBudget) -> Bool {
        guard value.count >= Int(search.length) else { return false }
        let allowance = scan.allowance(.index)
        guard allowance > 0 else {
            scan.noteRefused(.index)
            return true
        }
        let range = Int(search.offset)..<Int(search.offset + search.length)
        var budget = allowance
        let verdict = StringMatching.contains(value, UnsafeBufferPointer(rebasing: bytes.buffer[range]),
                                              failure: UnsafeBufferPointer(rebasing: failures.buffer[range]),
                                              folding: search.folding, budget: &budget)
        scan.spend(allowance - budget, from: .index)
        guard verdict != .unknown else {
            scan.noteRefused(.index)
            return true
        }
        return verdict == .yes
    }

    /// Set the bits of some rules.
    ///
    /// - Parameters:
    ///   - start: Their first position in ``marks``.
    ///   - count: How many.
    ///   - words: The candidates.
    @inline(__always)
    private func mark(_ start: Int32, _ count: Int32, _ words: inout ContiguousArray<UInt64>) {
        for index in Int(start)..<Int(start + count) {
            let position = Int(marks.buffer[index])
            words[position >> 6] |= 1 << UInt64(position & 63)
        }
    }

    /// Free every buffer. Call once, when nothing will read them again.
    func deallocate() {
        buckets.deallocate()
        probes.deallocate()
        masks.deallocate()
        nodes.deallocate()
        edgeBytes.deallocate()
        edgeNodes.deallocate()
        searches.deallocate()
        bytes.deallocate()
        failures.deallocate()
        marks.deallocate()
    }
}
