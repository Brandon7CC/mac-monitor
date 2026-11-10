//
//  IndicatorProgram.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import EndpointSecurity


// MARK: - Indicator program
/// One indicator's predicate as the Security Extension runs it: a flat program of plain values that
/// ``IndicatorCompiler`` made from the predicate's text, evaluated on an event's ``MessageValues`` (see
/// `IndicatorProgram+Evaluation.swift`).
///
/// Its nodes sit in one array, the root first, and a node's children are next to each other, so a node names them by
/// its first child and how many there are. A comparison's constants are in a table of their own, and their bytes in one
/// pool, each with the failure table its search needs (``StringMatching``). Evaluating one reads only these, the event
/// and the lane's ``MessageValueCache``.
///
/// It's `Equatable` and describes itself as a predicate (``description``), so a compiled rule can be tested and shown.
public struct IndicatorProgram: @unchecked Sendable {
    /// What a comparison does.
    public enum Operator: UInt8, Sendable {
        case equalTo, notEqualTo, lessThan, lessThanOrEqualTo, greaterThan, greaterThanOrEqualTo
        case `in`, beginsWith, endsWith, contains, like
    }

    /// How a comparison compares strings: `[c]` and `[d]`.
    public struct Options: OptionSet, Hashable, Sendable {
        /// The options' bits.
        public let rawValue: UInt8
        /// `[c]`: case-insensitive.
        public static let caseInsensitive = Options(rawValue: 1)
        /// `[d]`: diacritic-insensitive.
        public static let diacriticInsensitive = Options(rawValue: 2)

        /// - Parameter rawValue: The options' bits.
        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }
    }

    /// One step of the program.
    struct Node: Equatable, Sendable {
        /// What the node is.
        enum Kind: UInt8, Sendable {
            /// True when every child is: `count` children from `first`.
            case and
            /// True when any child is.
            case or
            /// True when its one child, at `first`, isn't.
            case not
            /// `TRUEPREDICATE` when `count` is 1, `FALSEPREDICATE` when it's 0.
            case truth
            /// A field compared with `count` constants from `first`: one, or a set for `IN`, or `LIKE`'s segments.
            case compare
            /// `ANY` of an array field's strings compared, as ``compare`` compares one.
            case anyCompare
            /// The event's type, by number, `==`, `!=` or `IN` the types its constants hold.
            case eventType
        }

        /// What it is.
        var kind: Kind
        /// A comparison's operator.
        var op: Operator = .equalTo
        /// A comparison's options.
        var options: Options = []
        /// The field a comparison reads.
        var field: IndicatorField = .esEventType
        /// The first child or constant.
        var first: Int32 = 0
        /// How many children or constants.
        var count: Int32 = 0

        /// The children's or constants' indices.
        var range: Range<Int> { Int(first)..<Int(first) + Int(count) }
    }

    /// A comparison's constant. Its fields are in the order that packs it into 32 bytes.
    struct Constant: Equatable, Sendable {
        /// What the constant is.
        enum Kind: UInt8, Sendable {
            case null, string, number
        }

        /// A number's value, or an event type's number.
        var number: Double = 0
        /// A string's bytes in ``IndicatorProgram/bytes``: as written, or lowered when it's ASCII and compared `[c]`.
        var offset: Int32 = 0
        var length: Int32 = 0
        /// Its failure table in ``IndicatorProgram/failures``, for a search, or -1 without one.
        var failure: Int32 = -1
        /// Its text in ``IndicatorProgram/strings``, as written, for the Foundation path, or -1.
        var string: Int32 = -1
        /// What it is.
        var kind: Kind
        /// Is the string all ASCII?
        var isASCII = true
        /// Is the number whole?
        var isInteger = false
    }

    /// The nodes, the root first.
    var nodes: ContiguousArray<Node>
    /// The comparisons' constants.
    var constants: ContiguousArray<Constant>
    /// The constants' bytes.
    var bytes: ContiguousArray<UInt8>
    /// The constants' failure tables (``StringMatching/failureTable(of:)``).
    var failures: ContiguousArray<Int32>
    /// The string constants as written, for the comparisons Foundation makes. Only a non-ASCII value or constant
    /// reads them.
    var strings: ContiguousArray<NSString>

    /// A program that's always true or always false.
    ///
    /// - Parameter truth: Its verdict.
    init(truth: Bool) {
        nodes = [Node(kind: .truth, count: truth ? 1 : 0)]
        constants = []
        bytes = []
        failures = []
        strings = []
    }

    /// The fields it reads, in order, each once.
    public var fields: [IndicatorField] {
        var seen = Set<IndicatorField>()
        return nodes.filter { [.compare, .anyCompare].contains($0.kind) }.map(\.field)
            .filter { seen.insert($0).inserted }
    }

    /// How many nodes it has.
    public var nodeCount: Int { nodes.count }

}


// MARK: - Equality
extension IndicatorProgram: Equatable {
    /// Two programs are the same when their nodes, constants, bytes and failure tables are: the strings are their
    /// constants' text again.
    ///
    /// - Parameters:
    ///   - lhs: A program.
    ///   - rhs: Another.
    /// - Returns: Whether they're the same program.
    public static func == (lhs: IndicatorProgram, rhs: IndicatorProgram) -> Bool {
        lhs.nodes == rhs.nodes && lhs.constants == rhs.constants && lhs.bytes == rhs.bytes
            && lhs.failures == rhs.failures
    }
}


// MARK: - Description
extension IndicatorProgram: CustomStringConvertible {
    /// The program as a predicate `NSPredicate(format:)` reads: `(event.exec.target.executable.name == "curl" OR
    /// ...)`. An event type is named, a `LIKE`'s pattern is written whole, and `TRUEPREDICATE` stands for a rule with
    /// nothing left to check once its type is known.
    public var description: String {
        describe(0)
    }

    /// - Parameter index: A node's index.
    /// - Returns: The node as a predicate.
    private func describe(_ index: Int) -> String {
        let node = nodes[index]
        switch node.kind {
        case .and, .or:
            let joint = node.kind == .and ? " AND " : " OR "
            return "(" + node.range.map(describe).joined(separator: joint) + ")"
        case .not:
            return "NOT " + describe(Int(node.first))
        case .truth:
            return node.count == 0 ? "FALSEPREDICATE" : "TRUEPREDICATE"
        case .eventType:
            let names = node.range.map { IndicatorValue.literal(eventTypeName(constants[$0])[...]) }
            return node.op == .in ? "es_event_type IN {" + names.joined(separator: ", ") + "}"
                : "es_event_type \(Self.symbol(of: node.op)) \(names[0])"
        case .compare, .anyCompare:
            let lead = node.kind == .anyCompare ? "ANY " : ""
            let options = (node.options.contains(.caseInsensitive) ? "c" : "")
                + (node.options.contains(.diacriticInsensitive) ? "d" : "")
            let comparison = Self.symbol(of: node.op) + (options.isEmpty ? "" : "[\(options)]")
            return lead + node.field.path + " " + comparison + " " + describeConstants(of: node)
        }
    }

    /// - Parameter node: A comparison.
    /// - Returns: Its constant, its set or its pattern, as a predicate writes it.
    private func describeConstants(of node: Node) -> String {
        if node.op == .like {
            return IndicatorValue.literal(node.range.map { strings[Int(constants[$0].string)] as String }
                .joined(separator: "*")[...])
        }
        let written = node.range.map { index -> String in
            let constant = constants[index]
            switch constant.kind {
            case .null: return "nil"
            case .number: return IndicatorValue.number(constant.number, isInteger: constant.isInteger).description
            case .string: return IndicatorValue.literal((strings[Int(constant.string)] as String)[...])
            }
        }
        return node.op == .in ? "{" + written.joined(separator: ", ") + "}" : written[0]
    }

    /// - Parameter constant: An event type's constant.
    /// - Returns: The type's name, as in `ES_EVENT_TYPE_NOTIFY_EXEC`.
    private func eventTypeName(_ constant: Constant) -> String {
        eventTypeToString(from: es_event_type_t(rawValue: UInt32(constant.number)))
    }

    /// - Parameter op: An operator.
    /// - Returns: How a predicate writes it.
    static func symbol(of op: Operator) -> String {
        switch op {
        case .equalTo: "=="
        case .notEqualTo: "!="
        case .lessThan: "<"
        case .lessThanOrEqualTo: "<="
        case .greaterThan: ">"
        case .greaterThanOrEqualTo: ">="
        case .in: "IN"
        case .beginsWith: "BEGINSWITH"
        case .endsWith: "ENDSWITH"
        case .contains: "CONTAINS"
        case .like: "LIKE"
        }
    }
}
