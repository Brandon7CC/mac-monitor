//
//  MessageValues.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Message values
/// An event's values for the fields the Security Extension evaluates indicators on (``IndicatorField``), read from
/// the `Message` a capture lane builds, before it's encoded or stored. Each is the value a predicate on the event's
/// record compares there (`ESMessage(from:)` encoded, read as ``PredicateRecord`` reads it), which
/// `MessageValuesParityTests` checks for every field on every event of the synthetic corpus, the fixtures, the lineage
/// trace and the macath recordings:
///
/// - `context` and `target_path` are "Not supported" where the event has none, as the store writes them.
/// - An exec's `command_line` is "" where it has none.
/// - A process's `codesigning_type` is "" when it has no executable: the store keeps the type only beside one.
/// - An executable's `name` is its path's last component, as `File/name` is.
/// - `iokit_open.driver_bundle_id` is `nil` before message version 10, which the store doesn't keep it for.
/// - A field of another event type than the event's is `nil`, as the record has no such object.
///
/// The message is borrowed: each read goes through one `switch` on the event to the one leaf it needs, and copies
/// none of the message, its event's payload or a process's executable on the way (an optimized build's disassembly
/// shows none of them copied). A string comes back as a slice of the event's own, which only retains its storage.
public enum MessageValues {
    /// What the store writes for an event's `context` or `target_path` when it has none.
    static let notSupported = "Not supported"

    /// One field's value on an event. A record field is read from the event's encoding alone, which a lane does
    /// once for all of its set's (``MessageValueCache``).
    ///
    /// - Parameters:
    ///   - field: The field.
    ///   - message: The event.
    /// - Returns: The value its record has there.
    public static func value(of field: IndicatorField, in message: borrowing Message) -> IndicatorValue {
        guard field.isDirect else {
            var value = IndicatorValue.null
            RecordPathTrie([field]).read(message) { _, found in value = found }
            return value
        }
        return switch field {
        case .esEventType: IndicatorValue(message.es_event_type)
        case .context: IndicatorValue(message.context ?? notSupported)
        case .targetPath: IndicatorValue(message.target_path ?? notSupported)
        case .processExecutablePath: process(.executablePath, of: message.process)
        case .processExecutableName: process(.executableName, of: message.process)
        case .processSigningID: process(.signingID, of: message.process)
        case .processTeamID: process(.teamID, of: message.process)
        case .processIsPlatformBinary: process(.isPlatformBinary, of: message.process)
        case .processCodesigningType: process(.codesigningType, of: message.process)
        case .processIsAdhocSigned: process(.isAdhocSigned, of: message.process)
        default: event(field, of: message.event, version: message.version)
        }
    }

    /// A field of the event's own object, under `event`.
    ///
    /// - Parameters:
    ///   - field: A field under `event`.
    ///   - event: The event.
    ///   - version: The message's version.
    /// - Returns: The value, or ``IndicatorValue/null`` when the event is of another type.
    private static func event(_ field: IndicatorField, of event: EventType, version: Int) -> IndicatorValue {
        switch event {
        case .exec(let exec): Self.exec(field, of: exec)
        case .close(let close) where field == .closeModified: IndicatorValue(close.modified)
        case .close(let close) where field == .closeFileType: IndicatorValue(close.file_type)
        case .close(let close) where field == .closeMachOType: IndicatorValue(close.mach_o_type)
        case .deleteextattr(let xattr) where field == .deleteextattrExtattr: IndicatorValue(xattr.extattr)
        case .iokit_open(let open) where field == .iokitOpenDriverBundleID && version >= 10:
            IndicatorValue(open.driver_bundle_id)
        case .iokit_open(let open) where field == .iokitOpenUserClientClass: IndicatorValue(open.user_client_class)
        case .uipc_connect(let connect) where field == .uipcConnectFileStatUID:
            IndicatorValue(Int(connect.file.stat.st_uid))
        case .xpc_connect(let connect) where field == .xpcConnectServiceName: IndicatorValue(connect.service_name)
        case .xpc_connect(let connect) where field == .xpcConnectServiceDomainTypeString:
            IndicatorValue(connect.service_domain_type_string)
        default: .null
        }
    }

    /// A field under `event.exec`.
    ///
    /// - Parameters:
    ///   - field: A field.
    ///   - exec: The exec.
    /// - Returns: The value, or ``IndicatorValue/null`` for a field that isn't under `event.exec`.
    private static func exec(_ field: IndicatorField, of exec: borrowing ProcessExecEvent) -> IndicatorValue {
        switch field {
        case .execCommandLine: IndicatorValue(exec.command_line ?? "")
        case .execEnv: .strings(exec.env)
        case .execScriptContent: IndicatorValue(exec.script_content)
        case .execExecutableAge: IndicatorValue(exec.executable_age_ms)
        case .execTargetSigningID: process(.signingID, of: exec.target)
        case .execTargetTeamID: process(.teamID, of: exec.target)
        case .execTargetIsPlatformBinary: process(.isPlatformBinary, of: exec.target)
        case .execTargetIsAdhocSigned: process(.isAdhocSigned, of: exec.target)
        case .execTargetCodesigningType: process(.codesigningType, of: exec.target)
        case .execTargetExecutablePath: process(.executablePath, of: exec.target)
        case .execTargetExecutableName: process(.executableName, of: exec.target)
        case .execTargetEUID: IndicatorValue(exec.target.euid)
        case .execTargetRUID: IndicatorValue(exec.target.ruid)
        default: .null
        }
    }

    /// A process's value that a field reads: the initiating process's, or an exec target's.
    private enum ProcessLeaf {
        case signingID, teamID, isPlatformBinary, isAdhocSigned, codesigningType, executablePath, executableName
    }

    /// One of a process's values.
    ///
    /// - Parameters:
    ///   - leaf: The value.
    ///   - process: The process.
    /// - Returns: The value its record has.
    private static func process(_ leaf: ProcessLeaf, of process: borrowing Process) -> IndicatorValue {
        switch leaf {
        case .signingID: IndicatorValue(process.signing_id)
        case .teamID: IndicatorValue(process.team_id)
        case .isPlatformBinary: IndicatorValue(process.is_platform_binary)
        case .isAdhocSigned: IndicatorValue(process.is_adhoc_signed)
        case .codesigningType: codesigningType(of: process)
        case .executablePath: IndicatorValue(process.executable?.path)
        case .executableName: name(ofPath: process.executable?.path)
        }
    }

    /// A process's `codesigning_type`, which the store keeps only beside an executable: "" without one.
    ///
    /// The executable is tested with a pattern, not `== nil`, which would compare a copy of it by `File`'s `==`.
    ///
    /// - Parameter process: The process.
    /// - Returns: The type's raw value, or "" without an executable.
    private static func codesigningType(of process: borrowing Process) -> IndicatorValue {
        if case .none = process.executable { return IndicatorValue("") }
        return IndicatorValue(process.codesigning_type.rawValue)
    }

    /// A file's `name`: its path's last component, as `NSString` gives it (`File/name`), sliced from the path where
    /// it doesn't end in "/", so it copies no bytes.
    ///
    /// - Parameter path: The file's path, or `nil` without a file.
    /// - Returns: The name, or ``IndicatorValue/null`` without a file.
    static func name(ofPath path: String?) -> IndicatorValue {
        guard let path else { return .null }
        let bytes = path.utf8
        let slash = UInt8(ascii: "/")
        guard let last = bytes.last, last != slash else {
            return IndicatorValue((path as NSString).lastPathComponent)
        }
        guard let separator = bytes.lastIndex(of: slash) else { return .string(path[...]) }
        return .string(Substring(bytes[bytes.index(after: separator)...]))
    }
}


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
        foundation.reset()
        (lastEventUnits, lastEventRefused) = (scan.spent, scan.refusedPools)
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
        let value = MessageValues.value(of: field, in: message)
        keep(value, for: field)
        return value
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
