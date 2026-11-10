//
//  StringMatching+Foundation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Foundation's comparisons
/// The comparisons of a value or constant that isn't all ASCII, which Foundation makes with the rule's options, as
/// `NSPredicate` does: `NSString`'s `compare(_:options:)` with `.literal` for `==` and `!=` with options, and
/// `range(of:options:)` for `BEGINSWITH` (`.anchored`), `ENDSWITH` (`.anchored` and `.backwards`) and `CONTAINS`.
/// Each is thread-safe, and no `NSPredicate` runs on a capture lane.
///
/// `LIKE` isn't Foundation's: `NSPredicate` matches it on both strings in NFKC, folded as the options say, then in NFKC
/// again, which ``likeUnits(of:options:)`` gives, and the pattern's segments are then matched on UTF-16 units as
/// ``StringMatching/like(_:segments:folding:segment:)`` matches bytes. A pattern has to be ASCII
/// (``IndicatorCompiler``): with a combining mark of its own, `NSPredicate`'s matching isn't that.
///
/// Each reads at most ``foundationLimit`` bytes of the value, its window: the first, or for `ENDSWITH` the last
/// (``FoundationStrings/truncations`` counts each value cut). On a longer value a comparison is decided only when the
/// window decides it for the whole value, and otherwise comes out undetermined (``IndicatorVerdict/unknown``), never
/// false, so its rule is listed as one the Security Extension couldn't rule out (`value_limit`):
///
/// - `CONTAINS` and `BEGINSWITH` on the first window are true when the match ends at least ``windowMargin`` UTF-16
///   units before the window does, and `ENDSWITH` on the last when it starts at least that far into it.
/// - `LIKE`, and `==` or `!=` with options, aren't compared at all.
///
/// Every Foundation call is charged to the event's ``ScanBudget`` before it runs, by the value's length and shape
/// (``ScanCost``, ``ValueShape``), so a command line that's ASCII but for a few scalars is decided whole up to about
/// 18 KiB against the shipped indicators, and one mostly of scalars that aren't ASCII up to less.
extension StringMatching {
    /// The most of a value Foundation compares: 64 KiB of its UTF-8.
    static let foundationLimit = 65_536
    /// How far from a window's cut a match on it has to be, in UTF-16 units, to stand for the whole value: whether a
    /// match ends where a character does depends on the scalars after it, which this keeps inside the window.
    static let windowMargin = 16

    /// - Parameter bytes: A value's UTF-8 length.
    /// - Returns: Whether Foundation compares only a window of it.
    @inline(__always)
    static func isTruncated(_ bytes: Int) -> Bool {
        bytes > foundationLimit
    }

    /// Does a match on a window stand for one on the whole value?
    ///
    /// - Parameters:
    ///   - range: Where the window has the match, or `nil` for none.
    ///   - window: The window.
    ///   - fromEnd: Is it the value's last window, rather than its first?
    /// - Returns: Whether the match is at least ``windowMargin`` units from the cut.
    static func isInsideWindow(_ range: NSRange?, of window: NSString, fromEnd: Bool) -> Bool {
        guard let range else { return false }
        return fromEnd ? range.location >= windowMargin : NSMaxRange(range) <= window.length - windowMargin
    }

    /// The part of a value Foundation compares, as an `NSString` that holds its own UTF-16, cut where a scalar starts.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - fromEnd: Its last ``foundationLimit`` bytes, rather than its first?
    ///   - limit: The most bytes to take.
    /// - Returns: The string, whether it's less than the value, and its shape.
    static func foundationString(_ value: Substring, fromEnd: Bool = false,
                                 limit: Int = foundationLimit) -> Part {
        withBytes(of: value) { part(of: $0, fromEnd: fromEnd, limit: limit) }
    }

    /// The part of a value Foundation compares, whether it's less than the value, and its shape.
    typealias Part = (string: NSString, truncated: Bool, shape: ValueShape)

    /// - Parameters:
    ///   - bytes: A value's UTF-8.
    ///   - fromEnd: Its last `limit` bytes, rather than its first?
    ///   - limit: The most bytes to take.
    /// - Returns: The part, cut where a scalar starts, as an `NSString`, whether it's less than the value, and its
    ///   shape. Bytes that aren't UTF-8, which no `String` holds, make an empty part.
    static func part(of bytes: UnsafeBufferPointer<UInt8>, fromEnd: Bool, limit: Int) -> Part {
        guard let base = bytes.baseAddress else { return ("", false, ValueShape()) }
        var range = 0..<bytes.count
        if bytes.count > limit, fromEnd {
            var start = bytes.count - limit
            while start < bytes.count, bytes[start] & 0xC0 == 0x80 { start += 1 }
            range = start..<bytes.count
        } else if bytes.count > limit {
            var end = limit
            while end > 0, bytes[end] & 0xC0 == 0x80 { end -= 1 }
            range = 0..<end
        }
        let string = NSString(bytes: base + range.lowerBound, length: range.count,
                              encoding: String.Encoding.utf8.rawValue) ?? ""
        return (string, range.count < bytes.count, ValueShape(of: UnsafeBufferPointer(rebasing: bytes[range])))
    }

    /// - Parameter options: A rule's options.
    /// - Returns: Foundation's.
    private static func compareOptions(_ options: IndicatorProgram.Options) -> NSString.CompareOptions {
        var compare: NSString.CompareOptions = []
        if options.contains(.caseInsensitive) { compare.insert(.caseInsensitive) }
        if options.contains(.diacriticInsensitive) { compare.insert(.diacriticInsensitive) }
        return compare
    }

    /// `==` with options: the same characters, literally, as the options compare them.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - constant: The constant.
    ///   - options: The rule's options.
    /// - Returns: Whether they're equal.
    static func equal(_ value: NSString, _ constant: NSString, options: IndicatorProgram.Options) -> Bool {
        value.compare(constant as String, options: compareOptions(options).union(.literal)) == .orderedSame
    }

    /// `BEGINSWITH`, `ENDSWITH` or `CONTAINS`. An empty constant is in nothing.
    ///
    /// - Parameters:
    ///   - op: The operator: one of those three.
    ///   - value: The value.
    ///   - constant: The constant.
    ///   - options: The rule's options.
    /// - Returns: Where the value has the constant there, or `nil`.
    static func search(_ op: IndicatorProgram.Operator, _ value: NSString, _ constant: NSString,
                       options: IndicatorProgram.Options) -> NSRange? {
        guard constant.length > 0 else { return nil }
        var compare = compareOptions(options)
        switch op {
        case .beginsWith: compare.insert(.anchored)
        case .endsWith: compare.formUnion([.anchored, .backwards])
        default: break
        }
        let range = value.range(of: constant as String, options: compare)
        return range.location == NSNotFound ? nil : range
    }

    /// A value's UTF-16 as `NSPredicate`'s `LIKE` matches it: in NFKC, folded as the options say, then in NFKC again.
    ///
    /// - Parameters:
    ///   - value: The value, as Foundation compares it.
    ///   - options: The rule's options.
    /// - Returns: Its units.
    static func likeUnits(of value: NSString, options: IndicatorProgram.Options) -> [UInt16] {
        var string = (value as String).precomposedStringWithCompatibilityMapping
        let compare = compareOptions(options)
        if !compare.isEmpty {
            string = string.folding(options: compare, locale: nil).precomposedStringWithCompatibilityMapping
        }
        return Array(string.utf16)
    }
}


// MARK: - Foundation strings
/// The values one lane has given Foundation for the event it's evaluating, so each is made once per event however
/// many comparisons read it: an event field's first and last ``StringMatching/foundationLimit`` bytes as `NSString`s,
/// with their shapes, and its `LIKE` units for each set of options. Kept in ``MessageValueCache``. Each is charged to
/// the event's ``ScanBudget`` when it's made, and never again that event; an array's element is made each time it's
/// compared.
///
/// **Threading:** not thread-safe. One per lane, used on the lane's queue.
struct FoundationStrings {
    /// One value, in one form.
    enum Entry {
        case string(NSString, ValueShape)
        case units([UInt16])
    }

    /// The forms per field: the start, the end, and `LIKE` units for each of the four sets of options.
    static let forms = 6

    /// Each field's forms, where made for this event.
    private var entries: ContiguousArray<Entry?>
    /// The entries made for this event, to forget at ``reset()``.
    private var made: ContiguousArray<Int>
    /// How many values Foundation compared only part of, since the lane started.
    private(set) var truncations = 0
    /// How many `NSString`s it made, since the lane started: what tests count to see a refused read made none.
    private(set) var stringsMade = 0

    /// An empty set, with room for every field.
    init() {
        entries = ContiguousArray(repeating: nil, count: IndicatorField.allCases.count * Self.forms)
        made = []
    }

    /// Forget the last event's values.
    mutating func reset() {
        for slot in made { entries[slot] = nil }
        made.removeAll(keepingCapacity: true)
    }

    /// A value as Foundation compares it: a field's, made the first time it's asked for after ``reset()``, or an
    /// array's element, made each time. Making it is charged first (``ScanCost/make(_:)``).
    ///
    /// - Parameters:
    ///   - field: The value's field, or `nil` for an array's element.
    ///   - fromEnd: Its end, for `ENDSWITH`, rather than its start?
    ///   - value: The value on the event.
    ///   - scan: The event's budget.
    ///   - pool: The pool the read spends from.
    /// - Returns: The string and its shape, or `nil` when making it didn't fit the budget.
    mutating func string(of field: IndicatorField?, fromEnd: Bool, value: Substring, scan: inout ScanBudget,
                         pool: ScanPool) -> (string: NSString, shape: ValueShape)? {
        let slot = field.map { Int($0.rawValue) * Self.forms + (fromEnd ? 1 : 0) }
        if let slot { grow(to: slot) }
        if let slot, case .string(let string, let shape) = entries[slot] { return (string, shape) }
        let bytes = value.utf8.count
        guard scan.charge(ScanCost.make(Swift.min(bytes, StringMatching.foundationLimit)), from: pool) else {
            return nil
        }
        let (string, truncated, shape) = StringMatching.foundationString(value, fromEnd: fromEnd)
        stringsMade += 1
        if truncated { truncations += 1 }
        if let slot { store(.string(string, shape), at: slot) }
        return (string, shape)
    }

    /// A value as `LIKE` matches it with a set of options: a field's, made the first time it's asked for, or an
    /// array's element's, made each time. Its string and its units are each charged first, the units by the string's
    /// shape.
    ///
    /// - Parameters:
    ///   - field: The value's field, or `nil` for an array's element.
    ///   - options: The rule's options.
    ///   - value: The value on the event, which isn't past Foundation's window.
    ///   - scan: The event's budget.
    ///   - pool: The pool the read spends from.
    /// - Returns: Its units, or `nil` when making them didn't fit the budget.
    mutating func likeUnits(of field: IndicatorField?, options: IndicatorProgram.Options, value: Substring,
                            scan: inout ScanBudget, pool: ScanPool) -> [UInt16]? {
        let slot = field.map { Int($0.rawValue) * Self.forms + 2 + Int(options.rawValue & 3) }
        if let slot { grow(to: slot) }
        if let slot, case .units(let units) = entries[slot] { return units }
        guard case let (string, shape)? = string(of: field, fromEnd: false, value: value, scan: &scan, pool: pool),
              scan.charge(ScanCost.likeUnits(value.utf8.count, shape), from: pool) else { return nil }
        let units = StringMatching.likeUnits(of: string, options: options)
        if let slot { store(.units(units), at: slot) }
        return units
    }

    /// Make room for a record field's forms, whose number can be past the direct fields' (``IndicatorField``).
    ///
    /// - Parameter slot: The slot to fit.
    @inline(__always)
    private mutating func grow(to slot: Int) {
        guard slot >= entries.count else { return }
        entries.append(contentsOf: repeatElement(nil, count: slot + Self.forms - entries.count))
    }

    /// - Parameters:
    ///   - entry: A value's form.
    ///   - slot: Where it's kept.
    private mutating func store(_ entry: Entry, at slot: Int) {
        entries[slot] = entry
        made.append(slot)
    }
}
