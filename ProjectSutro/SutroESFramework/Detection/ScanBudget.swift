//
//  ScanBudget.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation


// MARK: - Scan pools
/// Where a metered read's units come from: the index, one of the three fields an event can make large, or every other
/// field. Each large field has a ceiling of its own, so padding one blinds only the reads of that one.
enum ScanPool: Int, CaseIterable, Sendable {
    case index, commandLine, env, script, other

    /// Is it one of the three fields an event can make large, which share ``ScanBudget/largeLimit``?
    var isLarge: Bool { self != .index && self != .other }

    /// - Parameter mask: Pools by bit, as ``ScanBudget/refusedPools`` has them.
    /// - Returns: Their names, such as "commandLine, index", or "none".
    static func names(_ mask: UInt8) -> String {
        let names = allCases.filter { mask & 1 << UInt8($0.rawValue) != 0 }.map { "\($0)" }
        return names.isEmpty ? "none" : names.joined(separator: ", ")
    }
}


// MARK: - Scan budget
/// One event's indicator work, in scan units: one unit is about one step of a search, and every weight
/// (``ScanCost``) is set so the work it pays for takes at most 3 ns a unit on an M5 at `-O`. It counts work, not
/// time, so the same event and set give the same verdicts on every Mac. A lane keeps one in its
/// ``MessageValueCache``, reset for each event.
///
/// The event's allowance, ``eventLimit``, is split by where a read comes from (``ScanPool``):
///
/// - the index gets at most an eighth (``indexLimit``), and running out only costs it pruning;
/// - each of `command_line`, `env` and `script_content` gets at most half (``fieldLimit``), and the three together
///   five eighths (``largeLimit``);
/// - so every other field always has at least a quarter left, however the large ones are padded.
///
/// A read that doesn't fit is refused: its comparison comes out undetermined (``IndicatorVerdict/unknown``), never
/// false.
struct ScanBudget {
    /// An event's allowance: 2^18 units, at most about 0.79 ms at 3 ns a unit.
    static let eventLimit = 262_144
    /// The index's ceiling, an eighth of the event's.
    static let indexLimit = eventLimit / 8
    /// The ceiling of any one of `command_line`, `env` and `script_content`, half the event's.
    static let fieldLimit = eventLimit / 2
    /// The ceiling of those three together, five eighths of the event's.
    static let largeLimit = eventLimit / 8 * 5

    /// The units spent on this event.
    private(set) var spent = 0
    /// What's left of the event's allowance, the index's, the three large fields' together, and each one's, kept as
    /// what's left so ``allowance(_:)`` is a few comparisons. Spending past a ceiling unconditionally leaves one
    /// negative.
    private var eventRoom = eventLimit, indexRoom = indexLimit, largeRoom = largeLimit
    private var commandLineRoom = fieldLimit, envRoom = fieldLimit, scriptRoom = fieldLimit
    /// Was a read refused on this event, the index's included, or for the rule being evaluated?
    private(set) var refusedThisEvent = false, refusedThisRule = false
    /// The pools reads were refused of on this event, by bit (``ScanPool``), and how many reads were refused.
    private(set) var refusedPools: UInt8 = 0, refusals = 0
    /// The event's allowance, ``eventLimit`` but in tests, which set anything from 0 to `.max`. The pools' ceilings
    /// are the same fractions of it. Setting it starts a new event.
    var limit = eventLimit {
        didSet { reset() }
    }

    /// A pool's ceiling, as a fraction of ``limit``.
    ///
    /// - Parameter pool: The pool.
    /// - Returns: Its ceiling.
    func ceiling(_ pool: ScanPool) -> Int {
        switch pool {
        case .index: limit / 8
        case .other: limit
        default: limit / 2
        }
    }

    /// The units a pool can still spend on this event: the least of what's left of the event's, the pool's and,
    /// for a large field, the three's together.
    ///
    /// - Parameter pool: The pool.
    /// - Returns: The units, never negative.
    @inline(__always)
    func allowance(_ pool: ScanPool) -> Int {
        let room = switch pool {
        case .other: eventRoom
        case .index: Swift.min(eventRoom, indexRoom)
        case .commandLine: Swift.min(eventRoom, largeRoom, commandLineRoom)
        case .env: Swift.min(eventRoom, largeRoom, envRoom)
        case .script: Swift.min(eventRoom, largeRoom, scriptRoom)
        }
        return Swift.max(0, room)
    }

    /// Spend what a search used of its allowance.
    ///
    /// - Parameters:
    ///   - units: The units, at most its ``allowance(_:)``.
    ///   - pool: Its pool.
    @inline(__always)
    mutating func spend(_ units: Int, from pool: ScanPool) {
        spent += units
        eventRoom -= units
        switch pool {
        case .other: break
        case .index: indexRoom -= units
        case .commandLine: commandLineRoom -= units; largeRoom -= units
        case .env: envRoom -= units; largeRoom -= units
        case .script: scriptRoom -= units; largeRoom -= units
        }
    }

    /// Spend an operation's cost before it runs, if it fits.
    ///
    /// - Parameters:
    ///   - units: Its cost (``ScanCost``).
    ///   - pool: Its pool.
    /// - Returns: Whether it fits: `false` spends nothing and notes the read refused.
    @inline(__always)
    mutating func charge(_ units: Int, from pool: ScanPool) -> Bool {
        guard units <= allowance(pool) else {
            noteRefused(pool)
            return false
        }
        spend(units, from: pool)
        return true
    }

    /// Spend a cost that's paid whatever is left: working out once per field whether its value is ASCII, which every
    /// comparison of it needs. Only a field past 4 MiB, which Endpoint Security never delivers, could take a pool past
    /// its ceiling this way.
    ///
    /// - Parameters:
    ///   - units: The cost.
    ///   - pool: Its pool.
    mutating func spendUnconditionally(_ units: Int, from pool: ScanPool) {
        spend(units, from: pool)
    }

    /// Note that a read of a pool was refused, for this rule and this event.
    ///
    /// - Parameter pool: The pool that had too little left.
    mutating func noteRefused(_ pool: ScanPool) {
        refusedPools |= 1 << UInt8(pool.rawValue)
        refusals += 1
        refusedThisEvent = true
        refusedThisRule = true
    }

    /// Start evaluating a rule: its refusals are its own.
    @inline(__always)
    mutating func beginRule() {
        refusedThisRule = false
    }

    /// Start a new event, with ``limit`` as it is.
    @inline(__always)
    mutating func reset() {
        spent = 0
        (eventRoom, indexRoom, largeRoom) = (limit, limit / 8, limit / 8 * 5)
        (commandLineRoom, envRoom, scriptRoom) = (limit / 2, limit / 2, limit / 2)
        refusedThisEvent = false
        refusedThisRule = false
        refusedPools = 0
        refusals = 0
    }

    /// The units spent from a pool on this event.
    ///
    /// - Parameter pool: The pool.
    /// - Returns: Its units.
    func spent(from pool: ScanPool) -> Int {
        switch pool {
        case .other: spent - spent(from: .index) - largeSpent
        case .index: ceiling(.index) - indexRoom
        case .commandLine: ceiling(pool) - commandLineRoom
        case .env: ceiling(pool) - envRoom
        case .script: ceiling(pool) - scriptRoom
        }
    }

    /// The units the three large fields spent together on this event.
    var largeSpent: Int { limit / 8 * 5 - largeRoom }
}


// MARK: - Verdicts
/// A rule's or a comparison's verdict, three-valued (Kleene): `unknown` when a refused read or a value past
/// Foundation's window left it undecided. `AND` is `no` at its first `no` child, `OR` `yes` at its first `yes`, and
/// `NOT` keeps `unknown`, so turning any comparison's verdict into `unknown` never turns a `yes` into a `no`.
enum IndicatorVerdict: UInt8, Sendable {
    case no, yes, unknown

    /// - Parameter decided: A decided verdict.
    @inline(__always)
    init(_ decided: Bool) {
        self = decided ? .yes : .no
    }

    /// `NOT` it: `yes` and `no` swapped, `unknown` kept.
    @inline(__always)
    var negated: IndicatorVerdict {
        switch self {
        case .no: .yes
        case .yes: .no
        case .unknown: .unknown
        }
    }
}


// MARK: - Fields' pools
extension IndicatorField {
    /// The pool a read of the field spends from: its own for `command_line`, `env` and `script_content`, the shared
    /// one for every other, record fields' included.
    var scanPool: ScanPool {
        switch self {
        case .execCommandLine: .commandLine
        case .execEnv: .env
        case .execScriptContent: .script
        default: .other
        }
    }
}
