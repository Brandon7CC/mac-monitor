//
//  MessageValueCache.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Value cache
/// The values one capture lane has read from the event it's evaluating, so each field is read once per event however
/// many indicators compare it, with what string matching learned of them: whether each is ASCII, and the forms
/// Foundation compares (``FoundationStrings``). A lane keeps one and reuses it for every event: it allocates only when
/// it's made, and for a value that isn't ASCII.
///
/// It keeps the event's ``ScanBudget`` too, and counts, since the lane started, the values Foundation compared only
/// part of (``truncatedEvaluations``), the events that matched more indicators than a record lists
/// (``cappedEvents``), those whose budget ran out somewhere (``scanExhaustedEvents``), and those with indicators
/// left undetermined (``undeterminedEvents``).
///
/// **Threading:** not thread-safe. One per lane, used on the lane's queue.
public struct MessageValueCache {
    /// The record fields of the set evaluating an event, read from its encoding in one walk the first time one of
    /// them is asked for (``RecordPathTrie``). Each set gives its own as it starts an event.
    var recordPaths: RecordPathTrie?
    /// The table an event's ancestors are read from (``LineageField``), or `nil` when lineage isn't tracked, and
    /// every ancestor's field is `nil`.
    var lineage: ProcessLineage?
    /// The ancestors of this event's process along each chain (``ProcessLineage/Chain``), once a field of theirs has
    /// been asked for.
    private var ancestors = [[ProcessProgram]?](repeating: nil, count: ProcessLineage.Chain.allCases.count)
    /// Has this event's walk been made?
    private var walked = false
    /// Each field's value, by its raw value, where ``isRead`` says so.
    private var values: ContiguousArray<IndicatorValue>
    /// Whether each field's value has been read for this event.
    private var isRead: ContiguousArray<Bool>
    /// Whether each field's string is ASCII: 0 not known yet, 1 ASCII, 2 not.
    private var ascii: ContiguousArray<UInt8>
    /// The fields read for this event, to forget at ``reset()``.
    private var read: ContiguousArray<IndicatorField>
    /// The values given Foundation for this event.
    var foundation = FoundationStrings()
    /// This event's indicator work.
    var scan = ScanBudget()
    /// What saying what this event's hits matched has spent of its own allowance, so the event's hits share one
    /// (``CompiledIndicators/matched(roots:_:type:values:)``). `nil` until an event's first hit is explained.
    var explaining: ScanBudget?
    /// The units the last event spent, and the pools it was refused reads of, by bit (``ScanPool``): what
    /// ``reset()`` found, for the benchmarks.
    private(set) var lastEventUnits = 0, lastEventRefused: UInt8 = 0
    /// How many events matched more indicators than a record lists, since the lane started.
    public internal(set) var cappedEvents = 0
    /// How many events' indicator scan budget ran out somewhere, the index's included, since the lane started.
    public internal(set) var scanExhaustedEvents = 0
    /// How many events had indicators the Security Extension couldn't rule out, since the lane started.
    public internal(set) var undeterminedEvents = 0
    /// The bits of the rules an event is evaluated against (``IndicatorIndex``), with room for 4,096 rules of a type,
    /// so a lane allocates more only for a type with more.
    private var candidates = ContiguousArray<UInt64>(repeating: 0, count: 64)
    /// The sequence steps this event matched, in the set's order (``CompiledIndicators/stepRule(sequence:step:)``).
    /// Its room is kept from event to event.
    var stepMatches = ContiguousArray<Int32>()

    /// An empty cache, with room for every direct field. A record field's room is made when it's first read.
    public init() {
        let count = IndicatorField.allCases.count
        values = ContiguousArray(repeating: .null, count: count)
        isRead = ContiguousArray(repeating: false, count: count)
        ascii = ContiguousArray(repeating: 0, count: count)
        read = []
        read.reserveCapacity(count)
    }

    /// How many fields have been read for this event.
    public var readCount: Int { read.count }

    /// How many values Foundation compared only their first or last ``StringMatching/foundationLimit`` bytes of,
    /// since the lane started.
    public var truncatedEvaluations: Int { foundation.truncations }

    /// Take the lane's candidate bits for an event, at least `words` of them, so they're written while the cache
    /// reads the event's values. Give them back with ``returnCandidates(_:)``.
    ///
    /// - Parameter words: How many words the event's type needs.
    /// - Returns: The bits, which the cache doesn't hold until they're back.
    mutating func takeCandidates(_ words: Int) -> ContiguousArray<UInt64> {
        var taken = ContiguousArray<UInt64>()
        swap(&taken, &candidates)
        if taken.count < words { taken = ContiguousArray(repeating: 0, count: words) }
        return taken
    }

    /// Give back the candidate bits ``takeCandidates(_:)`` took.
    ///
    /// - Parameter words: The bits.
    mutating func returnCandidates(_ words: consuming ContiguousArray<UInt64>) {
        candidates = words
    }

    /// Forget the last event's values, before reading another's. It lets go of the last event's strings too, so a
    /// lane never holds a large one past its event.
    public mutating func reset() {
        for field in read {
            values[Int(field.rawValue)] = .null
            isRead[Int(field.rawValue)] = false
            ascii[Int(field.rawValue)] = 0
        }
        read.removeAll(keepingCapacity: true)
        walked = false
        for chain in ancestors.indices { ancestors[chain] = nil }
        foundation.reset()
        (lastEventUnits, lastEventRefused) = (scan.spent, scan.refusedPools)
        explaining = nil
        /// A budget nothing spent or refused is as new.
        if scan.spent != 0 || scan.refusals != 0 { scan.reset() }
    }

    /// Start evaluating a rule: the budget's refusals are its own.
    @inline(__always)
    mutating func beginRule() {
        scan.beginRule()
    }

    /// A field's value on the event, read the first time it's asked for after ``reset()``.
    ///
    /// - Parameters:
    ///   - field: The field.
    ///   - message: The event, the same one for every call until ``reset()``.
    /// - Returns: The value (``MessageValues/value(of:in:)``).
    public mutating func value(of field: IndicatorField, in message: borrowing Message) -> IndicatorValue {
        let slot = Int(field.rawValue)
        if slot < isRead.count, isRead[slot] { return values[slot] }
        guard field.isDirect else { return recordValue(of: field, in: message) }
        let value: IndicatorValue
        if let offset = field.lineageOffset {
            value = lineageValue(at: offset, in: message)
        } else {
            value = MessageValues.value(of: field, in: message)
        }
        keep(value, for: field)
        return value
    }

    /// An ancestor's field: the ancestors of the event's process are read from the lineage table once for the
    /// event and the field's chain, by its process's key, or by its parent's when the table hasn't heard of the
    /// process yet. When it has heard of neither, the parents are read from the system, and waited for when
    /// they're gone (``ProcessLineage/ancestors(of:parent:reading:at:chain:)``): a capture lane can be ahead of
    /// the client that tells the table of forks and execs.
    ///
    /// - Parameters:
    ///   - offset: The field's place among the lineage fields.
    ///   - message: The event.
    /// - Returns: The value, or ``IndicatorValue/null`` when lineage isn't tracked.
    private mutating func lineageValue(at offset: Int, in message: borrowing Message) -> IndicatorValue {
        guard let lineage else { return .null }
        let chain = LineageField.chain(at: offset)
        let slot = ProcessLineage.Chain.allCases.firstIndex(of: chain) ?? 0
        if ancestors[slot] == nil {
            let time = UInt64(clamping: message.mach_time)
            ancestors[slot] = Self.subject(of: message).map {
                lineage.ancestors(of: $0.key, parent: $0.parent, reading: true, at: time, chain: chain)
            } ?? []
        }
        return LineageField.value(at: offset, of: ancestors[slot] ?? [])
    }

    /// The process whose ancestors an event's lineage fields read: the program an exec starts, which has its
    /// process's ancestors and its own launched-by parent, and any other event's process.
    ///
    /// - Parameter message: The event.
    /// - Returns: The process's key and its parent's, as the event names them, or `nil` without an audit token.
    private static func subject(of message: borrowing Message) -> (key: ProcessKey, parent: ProcessKey?)? {
        if case .exec(let exec) = message.event, let token = exec.target.audit_token {
            return (ProcessKey(token), exec.target.parent_audit_token.map(ProcessKey.init))
        }
        guard let token = message.process.audit_token else { return nil }
        return (ProcessKey(token), message.process.parent_audit_token.map(ProcessKey.init))
    }

    /// A record field's value: every record field of the set is read in one walk the first time one is asked for,
    /// and one the walk didn't find is ``IndicatorValue/null``. One outside the set's, as when a program is evaluated
    /// on its own, is read alone.
    ///
    /// - Parameters:
    ///   - field: A record field.
    ///   - message: The event.
    /// - Returns: The value.
    private mutating func recordValue(of field: IndicatorField, in message: borrowing Message) -> IndicatorValue {
        if !walked {
            walked = true
            if let recordPaths {
                recordPaths.read(message) { found, value in keep(value, for: found) }
                for found in recordPaths.fields where !isKept(found) { keep(.null, for: found) }
            }
        }
        if isKept(field) { return values[Int(field.rawValue)] }
        let value = MessageValues.value(of: field, in: message)
        keep(value, for: field)
        return value
    }

    /// - Parameter field: A field.
    /// - Returns: Has its value been read for this event?
    @inline(__always)
    private func isKept(_ field: IndicatorField) -> Bool {
        Int(field.rawValue) < isRead.count && isRead[Int(field.rawValue)]
    }

    /// Keep a field's value for this event, making room for a record field's.
    ///
    /// - Parameters:
    ///   - value: The value.
    ///   - field: Its field.
    private mutating func keep(_ value: IndicatorValue, for field: IndicatorField) {
        let slot = Int(field.rawValue)
        if slot >= values.count {
            let more = slot + 1 - values.count
            values.append(contentsOf: repeatElement(.null, count: more))
            isRead.append(contentsOf: repeatElement(false, count: more))
            ascii.append(contentsOf: repeatElement(0, count: more))
        }
        values[slot] = value
        isRead[slot] = true
        read.append(field)
    }

    /// Is a field's string value all ASCII? Worked out once per event, after its value is read, and charged to its
    /// pool whatever is left (``ScanCost/isASCII(_:)``), as every comparison of it needs it.
    ///
    /// - Parameters:
    ///   - field: A field whose value ``value(of:in:)`` read.
    ///   - string: Its value.
    /// - Returns: Whether every byte is ASCII.
    mutating func isASCII(_ field: IndicatorField, _ string: Substring) -> Bool {
        if ascii[Int(field.rawValue)] != 0 { return ascii[Int(field.rawValue)] == 1 }
        return StringMatching.withBytes(of: string) { isASCII(field, bytes: $0) }
    }

    /// - Parameters:
    ///   - field: A field whose value ``value(of:in:)`` read.
    ///   - bytes: Its value's UTF-8.
    /// - Returns: Whether every byte is ASCII, worked out once per event.
    @inline(__always)
    mutating func isASCII(_ field: IndicatorField, bytes: UnsafeBufferPointer<UInt8>) -> Bool {
        let slot = Int(field.rawValue)
        if ascii[slot] == 0 {
            let units = ScanCost.isASCII(bytes.count)
            if units > 0 { scan.spendUnconditionally(units, from: field.scanPool) }
            ascii[slot] = StringMatching.isASCII(bytes) ? 1 : 2
        }
        return ascii[slot] == 1
    }

    /// A value as Foundation compares it (``FoundationStrings/string(of:fromEnd:value:scan:pool:)``).
    ///
    /// - Parameters:
    ///   - string: The value.
    ///   - field: Its field, whose string is kept, or `nil` for an array's element.
    ///   - fromEnd: Its end, rather than its start?
    ///   - pool: The pool the read spends from.
    /// - Returns: The string and its shape, or `nil` when making it didn't fit the budget.
    mutating func foundationString(_ string: Substring, field: IndicatorField?, fromEnd: Bool,
                                   pool: ScanPool) -> (string: NSString, shape: ValueShape)? {
        foundation.string(of: field, fromEnd: fromEnd, value: string, scan: &scan, pool: pool)
    }

    /// A value's `LIKE` units (``FoundationStrings/likeUnits(of:options:value:scan:pool:)``).
    ///
    /// - Parameters:
    ///   - string: The value.
    ///   - field: Its field, whose units are kept, or `nil` for an array's element.
    ///   - options: The comparison's options.
    ///   - pool: The pool the read spends from.
    /// - Returns: The units, or `nil` when making them didn't fit the budget.
    mutating func likeUnits(_ string: Substring, field: IndicatorField?, options: IndicatorProgram.Options,
                            pool: ScanPool) -> [UInt16]? {
        foundation.likeUnits(of: field, options: options, value: string, scan: &scan, pool: pool)
    }

    /// Run a search within what a pool has left, and spend what it used.
    ///
    /// - Parameters:
    ///   - pool: The pool.
    ///   - search: The search, given the units it may spend, which it lowers by what it spends.
    /// - Returns: Its verdict: ``IndicatorVerdict/unknown``, the read noted refused, when the units ran out first.
    @inline(__always)
    mutating func metered(_ pool: ScanPool, _ search: (inout Int) -> IndicatorVerdict) -> IndicatorVerdict {
        let allowance = scan.allowance(pool)
        var budget = allowance
        let verdict = search(&budget)
        scan.spend(allowance - budget, from: pool)
        if verdict == .unknown { scan.noteRefused(pool) }
        return verdict
    }
}
