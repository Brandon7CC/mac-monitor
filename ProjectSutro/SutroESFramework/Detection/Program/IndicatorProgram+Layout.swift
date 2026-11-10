//
//  IndicatorProgram+Layout.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Laying out a program
extension IndicatorProgram {
    /// Lay a draft out: its root first, each node's children next to each other.
    ///
    /// - Parameter draft: The draft.
    init(_ draft: IndicatorDraft) {
        self.init(truth: true)
        let root = place(draft)
        nodes[0] = root
    }

    /// - Parameter draft: A part of the draft.
    /// - Returns: Its node, with its children and constants placed.
    private mutating func place(_ draft: IndicatorDraft) -> Node {
        switch draft {
        case .and(let children):
            return Node(kind: .and, first: place(children), count: Int32(children.count))
        case .or(let children):
            return Node(kind: .or, first: place(children), count: Int32(children.count))
        case .not(let child):
            return Node(kind: .not, first: place([child]), count: 1)
        case .truth(let truth):
            return Node(kind: .truth, count: truth ? 1 : 0)
        case .eventType(let op, let types):
            let first = Int32(constants.count)
            constants.append(contentsOf: types.map { Constant(number: Double($0), kind: .number, isInteger: true) })
            return Node(kind: .eventType, op: op, first: first, count: Int32(types.count))
        case .compare(let comparison):
            let first = Int32(constants.count)
            for constant in comparison.constants { add(constant, for: comparison) }
            return Node(kind: comparison.isAny ? .anyCompare : .compare, op: comparison.op,
                        options: comparison.options, field: comparison.field, first: first,
                        count: Int32(constants.count) - first)
        }
    }

    /// Place nodes next to each other, then their children after them.
    ///
    /// - Parameter drafts: The nodes' drafts.
    /// - Returns: The first one's index.
    private mutating func place(_ drafts: [IndicatorDraft]) -> Int32 {
        let first = nodes.count
        nodes.append(contentsOf: repeatElement(Node(kind: .truth), count: drafts.count))
        for (offset, draft) in drafts.enumerated() {
            let node = place(draft)
            nodes[first + offset] = node
        }
        return Int32(first)
    }

    /// Add a comparison's constant: a `LIKE` pattern's segments between `*`, each its own.
    ///
    /// - Parameters:
    ///   - constant: The constant.
    ///   - comparison: Its comparison.
    private mutating func add(_ constant: IndicatorDraft.Constant, for comparison: IndicatorDraft.Comparison) {
        switch constant {
        case .null:
            constants.append(Constant(kind: .null))
        case .number(let number, let isInteger):
            constants.append(Constant(number: number, kind: .number, isInteger: isInteger))
        case .string(let pattern, _) where comparison.op == .like:
            for segment in pattern.split(separator: "*", omittingEmptySubsequences: false) {
                addString(String(segment), folding: comparison.options.contains(.caseInsensitive), searched: true)
            }
        case .string(let string, let held):
            let folding = comparison.op != .in && comparison.options.contains(.caseInsensitive)
            addString(string, held: held, folding: folding, searched: comparison.op == .contains)
        }
    }

    /// Add a string constant: its bytes, lowered when it's ASCII and folded, its failure table when it's searched for,
    /// and its text.
    ///
    /// - Parameters:
    ///   - text: The string, as written.
    ///   - held: The string as the predicate holds it, if it's one of the predicate's constants.
    ///   - folding: Is it compared `[c]`?
    ///   - searched: Is it searched for, so it needs a failure table?
    private mutating func addString(_ text: String, held: NSString? = nil, folding: Bool, searched: Bool) {
        var stored = Array(text.utf8)
        let isASCII = stored.allSatisfy { $0 < 0x80 }
        if folding, isASCII { stored = stored.map(StringMatching.lowered) }
        var constant = Constant(offset: Int32(bytes.count), length: Int32(stored.count), string: Int32(strings.count),
                                kind: .string, isASCII: isASCII)
        bytes.append(contentsOf: stored)
        if searched, isASCII, !stored.isEmpty {
            constant.failure = Int32(failures.count)
            failures.append(contentsOf: stored.withUnsafeBufferPointer { StringMatching.failureTable(of: $0) })
        }
        strings.append(held ?? NSString(string: text))
        constants.append(constant)
    }
}
