//
//  IndicatorProgram+Comparison.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Comparing strings
/// A program's string comparisons, each three-valued and metered: a search spends from its field's pool of the event's
/// ``ScanBudget``, Foundation's calls are charged before they run (``ScanCost``), and a read that doesn't fit, or a
/// value past Foundation's window that the window can't decide, comes out ``IndicatorVerdict/unknown``. A comparison
/// that's decided is exactly `NSPredicate`'s.
extension IndicatorProgram.View {
    /// One step of the program.
    typealias Node = IndicatorProgram.Node
    /// A comparison's constant.
    typealias Constant = IndicatorProgram.Constant

    /// A comparison's verdict on a string value.
    ///
    /// - Parameters:
    ///   - node: A comparison of a string.
    ///   - string: The value.
    ///   - field: The field it's the value of, or `nil` for an array's element, which isn't kept.
    ///   - pool: The pool its reads spend from.
    ///   - values: The lane's values for this event.
    /// - Returns: Its verdict.
    func compare(_ node: Node, _ string: Substring, field: IndicatorField?, pool: ScanPool,
                 _ values: inout MessageValueCache) -> IndicatorVerdict {
        if let decided = literal(node, string) { return decided }
        return StringMatching.withBytes(of: string) { bytes in
            let ascii = field.map { values.isASCII($0, bytes: bytes) } ?? StringMatching.isASCII(bytes)
            if ascii, let decided = compareBytes(node, bytes, pool: pool, &values) { return decided }
            return compareFoundation(node, string, bytes: bytes.count, field: field, pool: pool, &values)
        }
    }

    /// The verdicts that compare a value's bytes literally or not at all (``literal(_:count:equals:)``), of a field's
    /// value, whose bytes are read only when its length is a constant's.
    ///
    /// - Parameters:
    ///   - node: A comparison of a string.
    ///   - string: The value.
    /// - Returns: The verdict, or `nil` for a comparison that reads the value's characters, whatever the value.
    @inline(__always)
    func literal(_ node: Node, _ string: Substring) -> IndicatorVerdict? {
        literal(node, count: string.utf8.count) { constant in
            StringMatching.withBytes(of: string) { StringMatching.equal($0, bytes(of: constant), folding: false) }
        }
    }

    /// The same, of an array's element's bytes.
    ///
    /// - Parameters:
    ///   - node: A comparison of a string.
    ///   - bytes: The value's UTF-8.
    /// - Returns: The verdict, or `nil` for a comparison that reads the value's characters, whatever the value.
    @inline(__always)
    func literal(_ node: Node, _ bytes: UnsafeBufferPointer<UInt8>) -> IndicatorVerdict? {
        literal(node, count: bytes.count) { StringMatching.equal(bytes, self.bytes(of: $0), folding: false) }
    }

    /// The verdicts that compare a value's bytes literally or not at all: `IN`, a constant that isn't a string, `==`
    /// and `!=` without options, an empty constant's search, and an ordering of strings.
    ///
    /// - Parameters:
    ///   - node: A comparison of a string.
    ///   - count: The value's UTF-8 length.
    ///   - equals: Are the value's bytes a string constant's, of the same length?
    /// - Returns: The verdict, or `nil` for a comparison that reads the value's characters, whatever the value.
    @inline(__always)
    private func literal(_ node: Node, count: Int, equals: (Constant) -> Bool) -> IndicatorVerdict? {
        /// Is the value this string constant, byte for byte?
        /// - Parameter constant: One of the comparison's constants.
        /// - Returns: Whether the constant is a string of the value's length whose bytes the value has.
        func isLiterally(_ constant: Constant) -> Bool {
            constant.kind == .string && count == Int(constant.length) && equals(constant)
        }
        if node.op == .in { return IndicatorVerdict(node.range.contains { isLiterally(constants[$0]) }) }
        let constant = constants[Int(node.first)]
        guard constant.kind == .string else { return IndicatorVerdict(node.op == .notEqualTo) }
        switch node.op {
        case .equalTo, .notEqualTo:
            guard node.options.isEmpty else { return nil }
            return IndicatorVerdict(isLiterally(constant) == (node.op == .equalTo))
        case .beginsWith, .endsWith, .contains:
            return constant.length > 0 ? nil : .no
        case .like:
            return nil
        default:
            return .no
        }
    }

    /// A comparison of an ASCII value on its bytes, `[c]` folding ASCII letters and `[d]` doing nothing.
    ///
    /// - Parameters:
    ///   - node: A comparison that reads characters (``literal(_:_:)`` is `nil`).
    ///   - bytes: The value's UTF-8, all ASCII.
    ///   - pool: The pool its searches spend from.
    ///   - values: The lane's values for this event.
    /// - Returns: Its verdict, or `nil` when the constant isn't ASCII, which Foundation compares.
    func compareBytes(_ node: Node, _ bytes: UnsafeBufferPointer<UInt8>, pool: ScanPool,
                      _ values: inout MessageValueCache) -> IndicatorVerdict? {
        let folding = node.options.contains(.caseInsensitive)
        guard node.op != .like else {
            return values.metered(pool) { budget in
                StringMatching.like(bytes, segments: Int(node.count), folding: folding, budget: &budget) { index in
                    let constant = constants[Int(node.first) + index]
                    return (self.bytes(of: constant), failure(of: constant))
                }
            }
        }
        let constant = constants[Int(node.first)]
        guard constant.isASCII else { return nil }
        let pattern = self.bytes(of: constant)
        switch node.op {
        case .equalTo, .notEqualTo:
            return IndicatorVerdict(StringMatching.equal(bytes, pattern, folding: folding) == (node.op == .equalTo))
        case .beginsWith:
            return IndicatorVerdict(StringMatching.hasPrefix(bytes, pattern, folding: folding))
        case .endsWith:
            return IndicatorVerdict(StringMatching.hasSuffix(bytes, pattern, folding: folding))
        default:
            return values.metered(pool) { budget in
                StringMatching.contains(bytes, pattern, failure: failure(of: constant), folding: folding,
                                        budget: &budget)
            }
        }
    }

    /// A comparison Foundation makes, of a value or constant that isn't ASCII, on at most its window: charged before
    /// each call by the window's length and shape (``ScanCost``), and decided on a value past the window only where
    /// the window decides it. A value within the window has one form for every operator, so making it is charged once.
    ///
    /// - Parameters:
    ///   - node: A comparison that reads characters.
    ///   - string: The value.
    ///   - count: Its UTF-8 length.
    ///   - field: Its field, whose forms are kept, or `nil` for an array's element.
    ///   - pool: The pool its reads spend from.
    ///   - values: The lane's values for this event.
    /// - Returns: Its verdict.
    func compareFoundation(_ node: Node, _ string: Substring, bytes count: Int, field: IndicatorField?,
                           pool: ScanPool, _ values: inout MessageValueCache) -> IndicatorVerdict {
        let truncated = StringMatching.isTruncated(count)
        let part = min(count, StringMatching.foundationLimit)
        let constant = constants[Int(node.first)]
        let diacritics = node.options.contains(.diacriticInsensitive)
        switch node.op {
        case .equalTo, .notEqualTo, .beginsWith, .endsWith, .contains:
            let isEquality = node.op == .equalTo || node.op == .notEqualTo, fromEnd = node.op == .endsWith && truncated
            guard !isEquality || !truncated,
                  case let (value, shape)? = values.foundationString(string, field: field, fromEnd: fromEnd,
                                                                     pool: pool)
            else { return .unknown }
            let cost = switch node.op {
            case .endsWith: ScanCost.endsWith(part, shape, diacritics: diacritics)
            case .contains: ScanCost.contains(part, shape, diacritics: diacritics)
            default: ScanCost.anchored(constant: Int(constant.length), shape)
            }
            guard values.scan.charge(cost, from: pool) else { return .unknown }
            let other = strings[Int(constant.string)]
            guard !isEquality else {
                return IndicatorVerdict(StringMatching.equal(value, other, options: node.options)
                                        == (node.op == .equalTo))
            }
            let found = StringMatching.search(node.op, value, other, options: node.options)
            guard truncated else { return IndicatorVerdict(found != nil) }
            return StringMatching.isInsideWindow(found, of: value, fromEnd: fromEnd) ? .yes : .unknown
        case .like:
            guard !truncated else { return .unknown }
            guard let units = values.likeUnits(string, field: field, options: node.options, pool: pool),
                  values.scan.charge(ScanCost.likeCall, from: pool) else { return .unknown }
            return like(node, units: units, pool: pool, &values)
        default:
            return .no
        }
    }

    /// `LIKE` on a value that isn't ASCII, as `NSPredicate` matches it: its NFKC units, folded, against the ASCII
    /// pattern's, which are lowered already when the comparison folds. The pattern is widened into one temporary
    /// buffer, so a call allocates nothing.
    ///
    /// - Parameters:
    ///   - node: The comparison.
    ///   - units: The value's units (``StringMatching/likeUnits(of:options:)``).
    ///   - pool: The pool its searches spend from.
    ///   - values: The lane's values for this event.
    /// - Returns: Its verdict.
    func like(_ node: Node, units: [UInt16], pool: ScanPool, _ values: inout MessageValueCache) -> IndicatorVerdict {
        let total = node.range.reduce(0) { $0 + Int(constants[$1].length) }
        return withUnsafeTemporaryAllocation(of: UInt16.self, capacity: max(total, 1)) { wide in
            var offset = 0
            for index in node.range {
                for byte in bytes(of: constants[index]) {
                    wide[offset] = UInt16(byte)
                    offset += 1
                }
            }
            let pattern = UnsafeBufferPointer(wide)
            return units.withUnsafeBufferPointer { value in
                values.metered(pool) { budget in
                    StringMatching.like(value, segments: Int(node.count), folding: false, budget: &budget) { index in
                        let start = (0..<index).reduce(0) { $0 + Int(constants[Int(node.first) + $1].length) }
                        let constant = constants[Int(node.first) + index]
                        return (UnsafeBufferPointer(rebasing: pattern[start..<start + Int(constant.length)]),
                                failure(of: constant))
                    }
                }
            }
        }
    }

    // MARK: Constants
    /// - Parameter constant: A string constant.
    /// - Returns: Its bytes.
    @inline(__always)
    func bytes(of constant: Constant) -> UnsafeBufferPointer<UInt8> {
        UnsafeBufferPointer(rebasing: bytes[Int(constant.offset)..<Int(constant.offset) + Int(constant.length)])
    }

    /// - Parameter constant: A string constant.
    /// - Returns: Its failure table, or an empty one without one.
    @inline(__always)
    func failure(of constant: Constant) -> UnsafeBufferPointer<Int32> {
        guard constant.failure >= 0 else { return UnsafeBufferPointer(rebasing: failures[0..<0]) }
        let start = Int(constant.failure)
        return UnsafeBufferPointer(rebasing: failures[start..<start + Int(constant.length)])
    }
}
