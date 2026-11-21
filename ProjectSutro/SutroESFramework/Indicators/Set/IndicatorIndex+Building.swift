//
//  IndicatorIndex+Building.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Building the index
extension IndicatorIndex {
    /// Index a set's programs: for each event type, what each of its rules needs of an event of the type
    /// (``IndicatorProgram/View/necessity(root:eventType:)``).
    ///
    /// - Parameter programs: The set's programs and its rules for each type.
    init(_ programs: FrozenPrograms) {
        let view = programs.view
        var parts = Parts(pool: view.bytes)
        var buckets = ContiguousArray<Bucket>()
        buckets.reserveCapacity(programs.typeCount)
        for type in 0..<programs.typeCount {
            let needs = programs.slots(forType: type).map { slot in
                view.necessity(root: programs.root(of: programs.rule(at: slot)), eventType: type)
            }
            buckets.append(parts.add(needs))
        }
        self.buckets = Frozen(buckets)
        probes = Frozen(parts.probes)
        masks = Frozen(parts.masks)
        nodes = Frozen(parts.nodes)
        edgeBytes = Frozen(parts.edgeBytes)
        edgeNodes = Frozen(parts.edgeNodes)
        searches = Frozen(parts.searches)
        bytes = Frozen(parts.bytes)
        failures = Frozen(parts.failures)
        marks = Frozen(parts.marks)
    }

    /// The index's parts laid so far.
    private struct Parts {
        /// The programs' bytes, which the anchors' are among.
        let pool: UnsafeBufferPointer<UInt8>
        var probes = ContiguousArray<Probe>(), masks = ContiguousArray<UInt64>(), nodes = ContiguousArray<Node>()
        var edgeBytes = ContiguousArray<UInt8>(), edgeNodes = ContiguousArray<Int32>()
        var searches = ContiguousArray<Search>(), bytes = ContiguousArray<UInt8>(), failures = ContiguousArray<Int32>()
        var marks = ContiguousArray<Int32>()

        /// - Parameter pool: The programs' bytes.
        init(pool: UnsafeBufferPointer<UInt8>) {
            self.pool = pool
        }

        /// Lay one event type's index.
        ///
        /// - Parameter needs: What each of its rules needs, in order.
        /// - Returns: The type's bucket.
        mutating func add(_ needs: [IndicatorNecessity]) -> Bucket {
            let words = (needs.count + 63) / 64
            var bucket = Bucket(probes: Int32(probes.count), mask: Int32(masks.count), words: Int32(words))
            var mask = [UInt64](repeating: 0, count: words)
            var fields: [IndicatorField: FieldAnchors] = [:], order: [IndicatorField] = []
            for (position, need) in needs.enumerated() {
                switch need {
                case .never:
                    continue
                case .unconstrained:
                    mask[position >> 6] |= 1 << UInt64(position & 63)
                case .anyOf(let anchors):
                    for anchor in anchors {
                        if fields[anchor.field] == nil { order.append(anchor.field) }
                        fields[anchor.field, default: FieldAnchors()].add(anchor, Int32(position), pool: pool)
                    }
                }
            }
            masks.append(contentsOf: mask)
            for field in order { probes.append(add(field, fields[field]!)) }
            bucket.probeCount = Int32(probes.count) - bucket.probes
            return bucket
        }

        /// Lay one field's anchors.
        ///
        /// - Parameters:
        ///   - field: The field.
        ///   - anchors: Its anchors.
        /// - Returns: Its probe.
        private mutating func add(_ field: IndicatorField, _ anchors: FieldAnchors) -> Probe {
            var probe = Probe(field: field)
            probe.prefix = add(anchors.prefix)
            probe.foldedPrefix = add(anchors.foldedPrefix)
            probe.suffix = add(anchors.suffix)
            probe.foldedSuffix = add(anchors.foldedSuffix)
            probe.searches = Int32(searches.count)
            for literal in anchors.searches {
                var search = Search(offset: Int32(bytes.count), length: Int32(literal.bytes.count),
                                    folding: literal.folding)
                (search.marks, search.markCount) = add(marks: literal.positions)
                bytes.append(contentsOf: literal.bytes)
                failures.append(contentsOf: literal.bytes.withUnsafeBufferPointer {
                    StringMatching.failureTable(of: $0)
                })
                searches.append(search)
            }
            probe.searchCount = Int32(searches.count) - probe.searches
            (probe.every, probe.everyCount) = add(marks: anchors.every)
            return probe
        }

        /// Lay a trie's nodes from its literals, sorted: the literals under a node are next to each other, those that
        /// end at it first, and its children's are in order of their next byte. A node's edges are laid before its
        /// children, which are laid one after another from a stack, as deep as the longest literal.
        ///
        /// - Parameter trie: The trie's literals.
        /// - Returns: Its root, or -1 for an empty one.
        private mutating func add(_ trie: Trie) -> Int32 {
            guard !trie.literals.isEmpty else { return -1 }
            let fromEnd = trie.fromEnd
            let literals = trie.literals.sorted { $0.precedes($1, fromEnd: fromEnd) }
            let root = Int32(nodes.count)
            var pending = [(range: 0..<literals.count, depth: 0, edge: -1)]
            while let (range, depth, edge) = pending.popLast() {
                if edge >= 0 { edgeNodes[edge] = Int32(nodes.count) }
                var node = Node(), next = range.lowerBound
                while next < range.upperBound, literals[next].bytes.count == depth {
                    if literals[next].exact {
                        (node.exact, node.exactCount) = add(marks: literals[next].positions)
                    } else {
                        (node.marks, node.markCount) = add(marks: literals[next].positions)
                    }
                    next += 1
                }
                node.edges = Int32(edgeBytes.count)
                while next < range.upperBound {
                    let byte = literals[next].byte(depth, fromEnd: fromEnd)
                    var end = next + 1
                    while end < range.upperBound, literals[end].byte(depth, fromEnd: fromEnd) == byte { end += 1 }
                    pending.append((next..<end, depth + 1, edgeBytes.count))
                    edgeBytes.append(byte)
                    edgeNodes.append(-1)
                    next = end
                }
                node.edgeCount = Int32(edgeBytes.count) - node.edges
                nodes.append(node)
            }
            return root
        }

        /// - Parameter positions: Rules, by their position among their type's.
        /// - Returns: Where they start in ``marks``, and how many.
        private mutating func add(marks positions: [Int32]) -> (Int32, Int32) {
            let start = Int32(marks.count)
            marks.append(contentsOf: positions)
            return (start, Int32(positions.count))
        }
    }

    /// One field's anchors for one event type, gathered before they're laid.
    private struct FieldAnchors {
        /// Prefixes and whole values, as written and folded.
        var prefix = Trie(fromEnd: false), foldedPrefix = Trie(fromEnd: false)
        /// Suffixes, as written and folded, read from their end.
        var suffix = Trie(fromEnd: true), foldedSuffix = Trie(fromEnd: true)
        /// Each distinct literal searched for, and the rules that need it, in the order they come.
        var searches: [(bytes: [UInt8], folding: Bool, positions: [Int32])] = []
        /// Where each literal is in ``searches``, by its bytes and whether it's folded.
        var searchIndex: [SearchKey: Int] = [:]
        /// Every rule with an anchor on the field, each once.
        var every: [Int32] = []

        /// Add a rule's anchor.
        ///
        /// - Parameters:
        ///   - anchor: The anchor.
        ///   - position: The rule's position among its type's.
        ///   - pool: The programs' bytes, which the anchor's are among.
        mutating func add(_ anchor: IndicatorAnchor, _ position: Int32, pool: UnsafeBufferPointer<UInt8>) {
            if every.last != position { every.append(position) }
            let bytes = UnsafeBufferPointer(rebasing: pool[Int(anchor.offset)..<Int(anchor.offset + anchor.length)])
            switch (anchor.shape, anchor.folding) {
            case (.exact, false), (.prefix, false): prefix.insert(bytes, exact: anchor.shape == .exact, position)
            case (.exact, true), (.prefix, true): foldedPrefix.insert(bytes, exact: anchor.shape == .exact, position)
            case (.suffix, false): suffix.insert(bytes, exact: false, position)
            case (.suffix, true): foldedSuffix.insert(bytes, exact: false, position)
            case (.contains, let folding):
                let key = SearchKey(bytes: Array(bytes), folding: folding)
                if let index = searchIndex[key] {
                    if searches[index].positions.last != position { searches[index].positions.append(position) }
                } else {
                    searchIndex[key] = searches.count
                    searches.append((key.bytes, folding, [position]))
                }
            }
        }
    }

    /// A searched literal, as the index keeps each once.
    private struct SearchKey: Hashable {
        /// Its bytes.
        let bytes: [UInt8]
        /// Is it folded?
        let folding: Bool
    }

    /// A trie's distinct literals as they're gathered, laid as nodes once they're all in.
    private struct Trie {
        /// Are its literals read from their end?
        let fromEnd: Bool
        /// Each distinct literal, and the rules that need it, in order.
        var literals: [Literal] = []
        /// Where each literal is in ``literals``.
        var index: [Literal.Key: Int] = [:]

        /// Add a rule's literal.
        ///
        /// - Parameters:
        ///   - bytes: Its bytes, among the programs'.
        ///   - exact: Is it a whole value?
        ///   - position: The rule's position among its type's.
        mutating func insert(_ bytes: UnsafeBufferPointer<UInt8>, exact: Bool, _ position: Int32) {
            let key = Literal.Key(bytes: bytes, exact: exact)
            if let found = index[key] {
                if literals[found].positions.last != position { literals[found].positions.append(position) }
            } else {
                index[key] = literals.count
                literals.append(Literal(bytes: bytes, exact: exact, positions: [position]))
            }
        }
    }

    /// One of a trie's literals, its bytes among the programs', and the rules that need it.
    private struct Literal {
        /// A literal as a trie keeps each once: its bytes, and whether it's a whole value.
        struct Key: Hashable {
            /// Its bytes, among the programs'.
            let bytes: UnsafeBufferPointer<UInt8>
            /// Is it a whole value?
            let exact: Bool

            /// - Parameter hasher: Takes its bytes and whether it's whole.
            func hash(into hasher: inout Hasher) {
                hasher.combine(bytes: UnsafeRawBufferPointer(bytes))
                hasher.combine(exact)
            }

            /// - Parameters:
            ///   - lhs: A literal.
            ///   - rhs: Another.
            /// - Returns: Whether they're the same bytes, and both whole or not.
            static func == (lhs: Key, rhs: Key) -> Bool {
                lhs.exact == rhs.exact && lhs.bytes.elementsEqual(rhs.bytes)
            }
        }

        /// Its bytes, among the programs'.
        let bytes: UnsafeBufferPointer<UInt8>
        /// Is it a whole value?
        let exact: Bool
        /// The rules that need it, by their position among their type's, in order.
        var positions: [Int32]

        /// - Parameters:
        ///   - depth: How far into it, as a walk reads it.
        ///   - fromEnd: Is it read from its end?
        /// - Returns: Its byte there.
        @inline(__always)
        func byte(_ depth: Int, fromEnd: Bool) -> UInt8 {
            bytes[fromEnd ? bytes.count - 1 - depth : depth]
        }

        /// - Parameters:
        ///   - other: Another literal of the trie.
        ///   - fromEnd: Are they read from their end?
        /// - Returns: Whether it comes first, as a walk reads them, a literal before those it starts.
        func precedes(_ other: Literal, fromEnd: Bool) -> Bool {
            for depth in 0..<min(bytes.count, other.bytes.count) {
                let mine = byte(depth, fromEnd: fromEnd), theirs = other.byte(depth, fromEnd: fromEnd)
                if mine != theirs { return mine < theirs }
            }
            return bytes.count < other.bytes.count
        }
    }
}
