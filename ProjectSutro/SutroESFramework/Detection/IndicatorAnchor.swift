//
//  IndicatorAnchor.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Indicator anchor
/// A literal comparison an indicator can't match an event without: one of a rule's ASCII string comparisons that
/// ``IndicatorIndex`` checks for every rule of an event's type at once, so it evaluates only the rules whose anchors
/// an event has.
///
/// An anchor holds on an ASCII value exactly when the comparison it comes from does (the byte rules
/// ``IndicatorProgram/View`` uses): `==` and `IN` compare bytes, `BEGINSWITH`, `ENDSWITH` and `CONTAINS` compare
/// bytes folding ASCII letters for `[c]`, and `[d]` changes nothing on ASCII. A `LIKE` pattern gives the literal its
/// value has to start with, or end with. The index treats a value that isn't ASCII as having every anchor of its
/// field.
///
/// Its bytes are its constant's, where the programs it's taken from keep them (``IndicatorProgram/View/bytes``), so
/// indexing a set's anchors copies none of them: the programs' byte pool must outlive the index's building.
struct IndicatorAnchor: Hashable, Sendable {
    /// Where in the value the anchor's bytes have to be.
    enum Shape: UInt8, Sendable {
        /// The whole value.
        case exact
        /// Its start.
        case prefix
        /// Its end.
        case suffix
        /// Anywhere.
        case contains

        /// What checking an anchor of it costs, against a lookup in one walk of the value: a search reads the whole
        /// value.
        var cost: Int { self == .contains ? 8 : 1 }
    }

    /// The field it reads.
    let field: IndicatorField
    /// Where its bytes have to be.
    let shape: Shape
    /// Are the value's ASCII letters folded before they're compared? Its bytes are lowered already when they are.
    let folding: Bool
    /// Where its bytes start among its programs' bytes, and how many there are.
    let offset: Int32, length: Int32
}


// MARK: - Necessity
/// What a rule needs of an event of one type before it can match it.
enum IndicatorNecessity: Equatable, Sendable {
    /// It can't match one: a comparison of the event's type rules it out.
    case never
    /// Nothing the index checks: it's evaluated on every event of the type.
    case unconstrained
    /// At least one of these anchors.
    case anyOf([IndicatorAnchor])
}


// MARK: - Deriving anchors
extension IndicatorProgram {
    /// What the program needs of an event of one type before it can match it, as its set's index has it. Its
    /// anchors' bytes are the program's own (``bytes``).
    ///
    /// - Parameter eventType: The type's number.
    /// - Returns: What it needs.
    func necessity(eventType: Int) -> IndicatorNecessity {
        withView { $0.necessity(root: 0, eventType: eventType) }
    }
}

extension IndicatorProgram.View {
    /// What a node needs, before its anchors are gathered: what checking them costs.
    private enum Need: Equatable {
        case never, unconstrained, anchored(cost: Int)
    }

    /// What the program rooted at a node needs of an event of one type before it can match it: each comparison of the
    /// event's type is decided by the type, `AND` needs what its cheapest anchored child needs, `OR` needs one of
    /// what its children need, and `NOT` needs nothing the index checks. What each node needs is costed first, and
    /// only the anchors chosen are gathered.
    ///
    /// - Parameters:
    ///   - root: The program's root node.
    ///   - eventType: The type's number.
    /// - Returns: What it needs.
    func necessity(root: Int, eventType: Int) -> IndicatorNecessity {
        switch need(of: root, eventType) {
        case .never: return .never
        case .unconstrained: return .unconstrained
        case .anchored:
            var anchors: [IndicatorAnchor] = []
            gather(root, eventType, into: &anchors)
            return .anyOf(anchors)
        }
    }

    /// - Parameters:
    ///   - index: A node's index.
    ///   - eventType: The type's number.
    /// - Returns: What the node needs.
    private func need(of index: Int, _ eventType: Int) -> Need {
        let node = nodes[index]
        switch node.kind {
        case .and:
            return cheapestChild(of: node, eventType)?.need ?? .unconstrained
        case .or:
            var cost = 0, possible = false
            for child in node.range {
                switch need(of: child, eventType) {
                case .never: continue
                case .unconstrained: return .unconstrained
                case .anchored(let more): cost += more; possible = true
                }
            }
            return possible ? .anchored(cost: cost) : .never
        case .truth:
            return node.count == 0 ? .never : .unconstrained
        case .eventType:
            let found = node.range.contains { constants[$0].number == Double(eventType) }
            return found == (node.op != .notEqualTo) ? .unconstrained : .never
        case .compare:
            return leaf(node).map { .anchored(cost: $0.shape.cost * $0.constants.count) } ?? .unconstrained
        case .not, .anyCompare:
            return .unconstrained
        }
    }

    /// An `AND`'s child that needs the least to check, the first of those that cost the same, or `.never` when one
    /// can't match.
    ///
    /// - Parameters:
    ///   - node: An `AND`.
    ///   - eventType: The type's number.
    /// - Returns: The child and what it needs, or `nil` when none is anchored.
    private func cheapestChild(of node: IndicatorProgram.Node, _ eventType: Int) -> (index: Int, need: Need)? {
        var best: (index: Int, need: Need, cost: Int)?
        for child in node.range {
            let need = need(of: child, eventType)
            switch need {
            case .never: return (child, .never)
            case .unconstrained: continue
            case .anchored(let cost) where cost < best?.cost ?? .max: best = (child, need, cost)
            case .anchored: continue
            }
        }
        return best.map { ($0.index, $0.need) }
    }

    /// Gather the anchors an anchored node needs.
    ///
    /// - Parameters:
    ///   - index: The node's index.
    ///   - eventType: The type's number.
    ///   - anchors: The anchors so far.
    private func gather(_ index: Int, _ eventType: Int, into anchors: inout [IndicatorAnchor]) {
        let node = nodes[index]
        switch node.kind {
        case .and:
            if let child = cheapestChild(of: node, eventType) { gather(child.index, eventType, into: &anchors) }
        case .or:
            for child in node.range where need(of: child, eventType) != .never {
                gather(child, eventType, into: &anchors)
            }
        case .compare:
            guard let leaf = leaf(node) else { return }
            for index in leaf.constants {
                anchors.append(IndicatorAnchor(field: node.field, shape: leaf.shape, folding: leaf.folding,
                                               offset: constants[index].offset, length: constants[index].length))
            }
        case .not, .truth, .eventType, .anyCompare:
            return
        }
    }

    /// The anchors a comparison holds only when one of them does: their shape, whether they fold, and the constants
    /// whose bytes they are. A comparison the index can't check has none: one that isn't of a string with ASCII
    /// constants, `!=`, ordering, and a `LIKE` pattern that starts and ends with `*`.
    ///
    /// - Parameter node: A comparison.
    /// - Returns: Its anchors, or `nil`.
    private func leaf(_ node: IndicatorProgram.Node)
        -> (shape: IndicatorAnchor.Shape, folding: Bool, constants: Range<Int>)? {
        let range = node.range
        guard !range.isEmpty, range.allSatisfy({ constants[$0].kind == .string && constants[$0].isASCII }) else {
            return nil
        }
        let folding = node.options.contains(.caseInsensitive)
        let first = range.lowerBound..<range.lowerBound + 1
        switch node.op {
        case .in: return (.exact, false, range)
        case .equalTo: return (.exact, folding, first)
        case .beginsWith: return (.prefix, folding, first)
        case .endsWith: return (.suffix, folding, first)
        case .contains: return (.contains, folding, first)
        case .like:
            if range.count == 1 { return (.exact, folding, first) }
            if constants[range.lowerBound].length > 0 { return (.prefix, folding, first) }
            guard constants[range.upperBound - 1].length > 0 else { return nil }
            return (.suffix, folding, range.upperBound - 1..<range.upperBound)
        case .notEqualTo, .lessThan, .lessThanOrEqualTo, .greaterThan, .greaterThanOrEqualTo:
            return nil
        }
    }
}
