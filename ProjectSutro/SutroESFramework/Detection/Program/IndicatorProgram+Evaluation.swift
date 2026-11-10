//
//  IndicatorProgram+Evaluation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Evaluation
extension IndicatorProgram {
    /// Does an event match? The program's arrays are read in place while it's evaluated. Lanes evaluate a set's
    /// programs through ``CompiledIndicators``, which borrows the event. This one takes its own copy, for tests and
    /// single programs.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - eventType: Its type's number, or -1 for one Mac Monitor doesn't model.
    ///   - values: The lane's values for this event.
    /// - Returns: Whether it matches: `false` when it doesn't, or when its budget left it undetermined.
    func matches(_ message: Message, eventType: Int, values: inout MessageValueCache) -> Bool {
        verdict(message, eventType: eventType, values: &values) == .yes
    }

    /// The program's verdict on an event, within the event's budget (``MessageValueCache/scan``).
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - eventType: Its type's number, or -1 for one Mac Monitor doesn't model.
    ///   - values: The lane's values for this event.
    /// - Returns: Its verdict.
    func verdict(_ message: Message, eventType: Int, values: inout MessageValueCache) -> IndicatorVerdict {
        withView { $0.verdict(root: 0, message, eventType: eventType, values: &values) }
    }

    /// Run a body on the program as it's evaluated, its arrays read in place.
    ///
    /// - Parameter body: Reads the program, rooted at node 0.
    /// - Returns: What `body` returns.
    func withView<Result>(_ body: (View) -> Result) -> Result {
        nodes.withUnsafeBufferPointer { nodes in
            constants.withUnsafeBufferPointer { constants in
                bytes.withUnsafeBufferPointer { bytes in
                    failures.withUnsafeBufferPointer { failures in
                        strings.withUnsafeBufferPointer { strings in
                            body(View(nodes: nodes, constants: constants, bytes: bytes, failures: failures,
                                      strings: strings))
                        }
                    }
                }
            }
        }
    }

    /// Programs as they're evaluated: their nodes, constants, bytes, failure tables and strings in buffers that stay
    /// put, which ``CompiledIndicators`` holds for a whole set, so evaluating a rule reads no reference-counted memory
    /// but the event's own and, for a value or constant that isn't ASCII, a constant's `NSString`.
    ///
    /// It runs a program as `NSPredicate` evaluates its predicate on the event's record (checked against it by
    /// `StringMatchingTests`, `IndicatorFuzzTests` and `CompiledIndicatorsParityTests`):
    ///
    /// - `== nil` and `!= nil` test for a value. A missing value `!=` a constant is true. `==`, ordering, `IN`,
    ///   `BEGINSWITH`, `ENDSWITH`, `CONTAINS` and `LIKE` are false on one.
    /// - Numbers, and Booleans as 1 and 0, compare as numbers, as `NSNumber` does.
    /// - `ANY` over a missing or empty array is false.
    /// - `AND` and `OR` stop at the first child that decides them, in the order the compiler gave them, cheapest to
    ///   read first (``IndicatorDraft/readingCheapestFirst``).
    ///
    /// Its verdicts are three-valued (``IndicatorVerdict``): a comparison the event's ``ScanBudget`` refused, or that
    /// Foundation's window couldn't decide, is `unknown`, which an `AND` or `OR` passes over to its next child and
    /// gives as its own verdict only when no child decides it. So every `yes` and `no` is `NSPredicate`'s.
    ///
    /// It reads each field once per event, through the lane's ``MessageValueCache``, and allocates nothing for an
    /// ASCII value. A value or constant that isn't ASCII is compared by Foundation (``StringMatching``).
    struct View {
        /// The programs' nodes.
        let nodes: UnsafeBufferPointer<Node>
        /// Their comparisons' constants.
        let constants: UnsafeBufferPointer<Constant>
        /// Their constants' bytes.
        let bytes: UnsafeBufferPointer<UInt8>
        /// Their constants' failure tables.
        let failures: UnsafeBufferPointer<Int32>
        /// Their string constants, for Foundation's comparisons.
        let strings: UnsafeBufferPointer<NSString>

        /// Does an event match the program rooted at a node?
        ///
        /// - Parameters:
        ///   - root: The program's root node.
        ///   - message: The event.
        ///   - eventType: Its type's number, or -1 for one Mac Monitor doesn't model.
        ///   - values: The lane's values for this event.
        /// - Returns: Whether its verdict is `yes`.
        func matches(root: Int, _ message: borrowing Message, eventType: Int,
                     values: inout MessageValueCache) -> Bool {
            evaluate(root, message, eventType, &values) == .yes
        }

        /// The program rooted at a node's verdict on an event.
        ///
        /// - Parameters:
        ///   - root: The program's root node.
        ///   - message: The event.
        ///   - eventType: Its type's number, or -1 for one Mac Monitor doesn't model.
        ///   - values: The lane's values for this event.
        /// - Returns: Its verdict.
        func verdict(root: Int, _ message: borrowing Message, eventType: Int,
                     values: inout MessageValueCache) -> IndicatorVerdict {
            evaluate(root, message, eventType, &values)
        }

        /// - Parameters:
        ///   - index: A node's index.
        ///   - message: The event.
        ///   - eventType: Its type's number.
        ///   - values: The lane's values for this event.
        /// - Returns: The node's verdict.
        private func evaluate(_ index: Int, _ message: borrowing Message, _ eventType: Int,
                              _ values: inout MessageValueCache) -> IndicatorVerdict {
            let node = nodes[index]
            switch node.kind {
            case .and, .or:
                let decider: IndicatorVerdict = node.kind == .and ? .no : .yes
                var verdict = decider.negated
                for child in node.range {
                    let child = evaluate(child, message, eventType, &values)
                    if child == decider { return decider }
                    if child == .unknown { verdict = .unknown }
                }
                return verdict
            case .not:
                return evaluate(Int(node.first), message, eventType, &values).negated
            case .truth:
                return IndicatorVerdict(node.count != 0)
            case .eventType:
                let found = node.range.contains { constants[$0].number == Double(eventType) }
                return IndicatorVerdict(node.op == .notEqualTo ? !found : found)
            case .compare:
                switch values.value(of: node.field, in: message) {
                case .null: return IndicatorVerdict(isTrueOnNil(node))
                case .number(let number, _): return IndicatorVerdict(compare(node, number))
                case .string(let string): return compare(node, string, field: node.field, pool: node.field.scanPool,
                                                         &values)
                case .strings: return .no
                }
            case .anyCompare:
                guard case .strings(let elements) = values.value(of: node.field, in: message) else { return .no }
                return any(node, elements, &values)
            }
        }

        /// `ANY` of an array's strings, in two passes, which is exact as `ANY` asks only whether some element
        /// matches. The first visits each element's own storage, charging ``ScanCost/element(_:)``, compares an
        /// ASCII one on its bytes, and leaves the rest. The second, only when the first found no match and left one,
        /// sends those to Foundation. So non-ASCII elements can't spend the pool before an ASCII match is read. The
        /// second goes on past an element its pool refused, as a later, smaller one may still fit and match.
        ///
        /// - Parameters:
        ///   - node: An `ANY` comparison.
        ///   - elements: The array.
        ///   - values: The lane's values for this event.
        /// - Returns: `yes` when an element matches, `unknown` when one was undetermined or not reached, else `no`.
        private func any(_ node: Node, _ elements: [String], _ values: inout MessageValueCache) -> IndicatorVerdict {
            let pool = node.field.scanPool, searches = node.op == .contains || node.op == .like
            var verdict = IndicatorVerdict.no, deferred = false, refused = false
            /// The first pass keeps its own account, spent at every exit and before each search, which spends too.
            var room = values.scan.allowance(pool), used = 0
            defer { values.scan.spend(used, from: pool) }
            for var element in elements {
                let seen: IndicatorVerdict? = element.withUTF8 { bytes in
                    let cost = ScanCost.element(bytes.count)
                    guard cost <= room - used else {
                        refused = true
                        return .unknown
                    }
                    used += cost
                    if let decided = literal(node, bytes) { return decided }
                    guard StringMatching.isASCII(bytes) else { return nil }
                    guard searches else { return compareBytes(node, bytes, pool: pool, &values) }
                    values.scan.spend(used, from: pool)
                    used = 0
                    defer { room = values.scan.allowance(pool) }
                    return compareBytes(node, bytes, pool: pool, &values)
                }
                guard !refused else {
                    values.scan.noteRefused(pool)
                    return .unknown
                }
                switch seen {
                case .yes: return .yes
                case .unknown: verdict = .unknown
                case nil: deferred = true
                case .no: continue
                }
            }
            values.scan.spend(used, from: pool)
            used = 0
            guard deferred else { return verdict }
            let everyOne = !constants[Int(node.first)].isASCII
            for element in elements {
                guard everyOne || !StringMatching.isASCII(element[...]) else { continue }
                switch compareFoundation(node, element[...], bytes: element.utf8.count, field: nil, pool: pool,
                                         &values) {
                case .yes: return .yes
                case .unknown: verdict = .unknown
                case .no: continue
                }
            }
            return verdict
        }

        /// A comparison's verdict on a missing value: true only for `!=` a constant, and for `== nil`.
        ///
        /// - Parameter node: The comparison.
        /// - Returns: Its verdict.
        private func isTrueOnNil(_ node: Node) -> Bool {
            switch node.op {
            case .equalTo: constants[Int(node.first)].kind == .null
            case .notEqualTo: constants[Int(node.first)].kind != .null
            default: false
            }
        }

        /// - Parameters:
        ///   - node: A comparison of a number.
        ///   - number: The value.
        /// - Returns: Its verdict.
        private func compare(_ node: Node, _ number: Double) -> Bool {
            if node.op == .in {
                return node.range.contains { constants[$0].kind == .number && constants[$0].number == number }
            }
            let constant = constants[Int(node.first)]
            guard constant.kind == .number else { return node.op == .notEqualTo }
            switch node.op {
            case .equalTo: return number == constant.number
            case .notEqualTo: return number != constant.number
            case .lessThan: return number < constant.number
            case .lessThanOrEqualTo: return number <= constant.number
            case .greaterThan: return number > constant.number
            case .greaterThanOrEqualTo: return number >= constant.number
            default: return false
            }
        }
    }
}
