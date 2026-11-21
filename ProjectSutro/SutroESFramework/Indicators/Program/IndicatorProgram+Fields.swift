//
//  IndicatorProgram+Fields.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Comparing two fields
/// A field compared with another field of the same event (``IndicatorDraft/FieldComparison``), decided as
/// `NSPredicate` decides the two values on the record (`StringMatchingTests+Fields.swift` checks every operator,
/// option and missing side against it):
///
/// - Two missing values are equal, so `==`, `<=` and `>=` are true on them, and every other operator false.
/// - A missing value differs from every present one: only `!=` is true.
/// - Numbers, and Booleans as 1 and 0, compare as numbers. Two whole numbers past 2^53 that a `Double` holds as one
///   are undetermined, as only `NSNumber` tells them apart.
/// - `==` and `!=` without options compare bytes, as with a constant.
/// - With both values ASCII, `[c]` folds both sides' letters and `[d]` does nothing, and `BEGINSWITH` and `ENDSWITH`
///   compare bytes. An empty right side starts and ends nothing.
/// - Otherwise Foundation compares, as with a constant (``StringMatching``), the right side whole and the left on its
///   window: a right side past 64 KiB is undetermined.
///
/// Reading both fields counts against the event's ``ScanBudget``: each value's ASCII check against its own pool,
/// each `NSString` made against its own, and the comparison against both (``ScanBudget/charge(_:from:and:)``). A
/// comparison that doesn't fit is undetermined, never false.
extension IndicatorProgram.View {
    /// A field comparison's verdict on an event.
    ///
    /// - Parameters:
    ///   - node: A ``IndicatorProgram/Node/Kind/fieldCompare``.
    ///   - message: The event.
    ///   - values: The lane's values for this event.
    /// - Returns: Its verdict.
    func compareFields(_ node: Node, _ message: borrowing Message,
                       _ values: inout MessageValueCache) -> IndicatorVerdict {
        let left = values.value(of: node.field, in: message)
        let right = values.value(of: node.other, in: message)
        switch (left, right) {
        case (.null, .null):
            switch node.op {
            case .equalTo, .lessThanOrEqualTo, .greaterThanOrEqualTo: return .yes
            default: return .no
            }
        case (.null, _), (_, .null):
            return IndicatorVerdict(node.op == .notEqualTo)
        case let (.number(left, _), .number(right, _)):
            return compareNumbers(node.op, left, right)
        case let (.string(left), .string(right)):
            return compareStrings(node, left, right, &values)
        default:
            /// Values of two kinds, which the compiler's check of the schema's kinds leaves no field to give.
            return IndicatorVerdict(node.op == .notEqualTo)
        }
    }

    /// - Parameters:
    ///   - op: The operator.
    ///   - left: The left side's number.
    ///   - right: The right side's.
    /// - Returns: The verdict, `unknown` when they're one `Double` at or past 2^53, which may be two whole numbers.
    private func compareNumbers(_ op: IndicatorProgram.Operator, _ left: Double, _ right: Double) -> IndicatorVerdict {
        if left == right, left.magnitude >= IndicatorCompiler.maxInteger { return .unknown }
        switch op {
        case .equalTo: return IndicatorVerdict(left == right)
        case .notEqualTo: return IndicatorVerdict(left != right)
        case .lessThan: return IndicatorVerdict(left < right)
        case .lessThanOrEqualTo: return IndicatorVerdict(left <= right)
        case .greaterThan: return IndicatorVerdict(left > right)
        case .greaterThanOrEqualTo: return IndicatorVerdict(left >= right)
        default: return .no
        }
    }

    /// Two strings: on their bytes where that's `NSPredicate`'s answer, and otherwise by Foundation.
    ///
    /// - Parameters:
    ///   - node: The comparison.
    ///   - left: The left side's value.
    ///   - right: The right side's value.
    ///   - values: The lane's values for this event.
    /// - Returns: Its verdict.
    private func compareStrings(_ node: Node, _ left: Substring, _ right: Substring,
                                _ values: inout MessageValueCache) -> IndicatorVerdict {
        let pools = (node.field.scanPool, node.other.scanPool)
        let isEquality = node.op == .equalTo || node.op == .notEqualTo
        return StringMatching.withBytes(of: left) { leftBytes in
            StringMatching.withBytes(of: right) { rightBytes in
                if let decided = decidedByLength(node, leftBytes.count, rightBytes.count) { return decided }
                let ascii = !isEquality || !node.options.isEmpty
                    ? values.isASCII(node.field, bytes: leftBytes) && values.isASCII(node.other, bytes: rightBytes)
                    : true
                guard ascii else {
                    return compareFoundation(node, left, leftBytes.count, right, rightBytes.count, &values)
                }
                /// Folding ASCII letters keeps a value's length.
                if isEquality, leftBytes.count != rightBytes.count { return IndicatorVerdict(node.op == .notEqualTo) }
                if !isEquality, leftBytes.count < rightBytes.count { return .no }
                guard values.scan.charge(ScanCost.pair(rightBytes.count), from: pools.0, and: pools.1) else {
                    return .unknown
                }
                let folding = node.options.contains(.caseInsensitive)
                switch node.op {
                case .equalTo, .notEqualTo:
                    let same = StringMatching.equalPair(leftBytes, rightBytes, folding: folding)
                    return IndicatorVerdict(same == (node.op == .equalTo))
                case .beginsWith:
                    return IndicatorVerdict(StringMatching.hasPrefixPair(leftBytes, rightBytes, folding: folding))
                case .endsWith:
                    return IndicatorVerdict(StringMatching.hasSuffixPair(leftBytes, rightBytes, folding: folding))
                default:
                    return .no
                }
            }
        }
    }

    /// The verdicts two values' lengths give without reading them: `==` and `!=` without options of two lengths,
    /// which compare bytes, and an empty right side, which no value starts or ends with.
    ///
    /// - Parameters:
    ///   - node: The comparison.
    ///   - left: The left side's UTF-8 length.
    ///   - right: The right side's.
    /// - Returns: The verdict, or `nil` when the values have to be read.
    @inline(__always)
    private func decidedByLength(_ node: Node, _ left: Int, _ right: Int) -> IndicatorVerdict? {
        switch node.op {
        case .equalTo, .notEqualTo:
            node.options.isEmpty && left != right ? IndicatorVerdict(node.op == .notEqualTo) : nil
        case .beginsWith, .endsWith:
            right == 0 ? .no : nil
        default:
            .no
        }
    }

    /// Two strings Foundation compares, one of which isn't ASCII, with the rule's options: the left side on at most
    /// its window, and the right whole. Each `NSString` is charged to its own field's pool as it's made, and the
    /// comparison to both. A right side past the window, or a left one that the window can't decide, is
    /// undetermined.
    ///
    /// - Parameters:
    ///   - node: The comparison.
    ///   - left: The left side's value.
    ///   - leftCount: Its UTF-8 length.
    ///   - right: The right side's value.
    ///   - rightCount: Its UTF-8 length.
    ///   - values: The lane's values for this event.
    /// - Returns: Its verdict.
    private func compareFoundation(_ node: Node, _ left: Substring, _ leftCount: Int, _ right: Substring,
                                   _ rightCount: Int, _ values: inout MessageValueCache) -> IndicatorVerdict {
        let truncated = StringMatching.isTruncated(leftCount)
        let isEquality = node.op == .equalTo || node.op == .notEqualTo, fromEnd = node.op == .endsWith && truncated
        guard !StringMatching.isTruncated(rightCount), !isEquality || !truncated,
              case let (value, leftShape)? = values.foundationString(left, field: node.field, fromEnd: fromEnd,
                                                                     pool: node.field.scanPool),
              case let (other, rightShape)? = values.foundationString(right, field: node.other, fromEnd: false,
                                                                      pool: node.other.scanPool)
        else { return .unknown }
        let part = min(leftCount, StringMatching.foundationLimit)
        let diacritics = node.options.contains(.diacriticInsensitive)
        let cost = node.op == .endsWith
            ? ScanCost.endsWithPair(part, leftShape, rightCount, rightShape, diacritics: diacritics)
            : ScanCost.anchoredPair(rightCount, leftShape, rightShape, diacritics: diacritics)
        guard values.scan.charge(cost, from: node.field.scanPool, and: node.other.scanPool) else { return .unknown }
        guard !isEquality else {
            return IndicatorVerdict(StringMatching.equal(value, other, options: node.options) == (node.op == .equalTo))
        }
        let found = StringMatching.search(node.op, value, other, options: node.options)
        guard truncated else { return IndicatorVerdict(found != nil) }
        return StringMatching.isInsideWindow(found, of: value, fromEnd: fromEnd) ? .yes : .unknown
    }
}
