//
//  SequenceTable.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation
import OSLog
import os


// MARK: - Sequence tables
/// One sequence's open chains (``SequenceChains``): the steps matched so far by events tied together, waiting for the
/// rest. Every capture lane advances it as its events match the sequence's steps (``advance(_:at:capacity:)``), under
/// a lock of its own, so only a step match takes it, and lanes matching different sequences never wait on each other.
///
/// - **Ordered:** a chain waits for one step, kept under the key that step's event must have (``SequenceProgram``).
///   An event that matches the step advances it, if it's within the window of the chain's first step and not before
///   the step it follows. The last step completes it. Where two chains would wait for one step under one key, the
///   one that started later takes the key once both have come, in time order: its window ends later.
/// - **Steps in time, not in arrival:** each lane hands its events over in its own order, so a step on another lane
///   than the steps before it can come before the step it follows, whose lane is behind, or whose app's exec is held
///   for Launch Services. Such a step that advances no chain is kept, as an early step, until the latest event is
///   ``SequenceChains/lateness`` past it, and a chain that comes to wait for it takes it then, if it follows in time.
///   Up to ``SequenceChains/variants`` chains wait for it under one key, so one handed over late still advances the
///   chain it follows in time. The event whose arrival completes the chain is the one tagged: usually the last
///   step's, and the late one's when a step came late. A chain never takes two steps from one event.
/// - **Unordered:** a chain is kept under its `by` key, with the latest time each step matched and the event that
///   matched it. It completes when a window around an event holds at least ``SequenceProgram/atLeast`` of its steps,
///   each matched by a different event (``SequenceWindow``). An event a lane hands over late is judged at its time.
/// - A completed chain is gone, so the next match of its steps starts another. Only the completing event is tagged.
/// - A chain is dropped as it's found once no event a lane may still hand over can join it: its window and the
///   lateness have passed since the latest event. Past the cap the table drops its oldest chain, by when it last
///   changed, and counts it (``evictions``). Early steps have a cap of their own, a quarter of the chains', so a burst
///   of them never drops a waiting chain (``earlyDrops``).
/// - An event more than 5 minutes behind the latest the table has seen means the clock went back, and the table
///   forgets its chains (``SequenceChains/observe(_:)``). A smaller step back can keep a key's chains from advancing
///   until the clock catches up.
///
/// Chains live in memory alone: a restart forgets them. Each capture session has its own tables
/// (``SessionChains``), so each advances its sequences with its own events once, and a session given a new set keeps
/// the tables of the sequences that didn't change, so changing the indicators doesn't forget them. Each passes its own
/// share of its budget as it advances a table, so a set that's built and refused changes nothing about the set in
/// use.
///
/// **Memory:** a chain or early step is 96 bytes and its key 24, in a dictionary with room for up to 8/3 of the most
/// it held, rebuilt smaller once most are gone, and up to twice as many in line at 32 bytes each, in an array up to
/// twice that: about 14 MiB for ``totalChains``, and 3.5 MiB more for their early steps, at most, plus 16 bytes for
/// each value one keeps for a later join. They're dropped as later events find them dead. A `macmonitor stream`'s
/// session has a quarter of that.
///
/// **Threading:** any lane's. Its state is behind ``state``'s lock.
final class SequenceTable: @unchecked Sendable {
    /// The most chains every sequence of a set holds together.
    static let totalChains = 32_768
    /// The fewest chains a sequence of Mac Monitor's session holds, however many sequences share ``totalChains``: its
    /// share with a set's most indicators, ``IndicatorLimits/maxIndicators``, each a sequence.
    static let minimumChains = totalChains / IndicatorLimits.maxIndicators
    /// Logs a table's first eviction.
    private static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension",
                                       category: "SequenceTable")

    /// The chains, and a test's cap.
    private struct State {
        /// The chains.
        var chains = SequenceChains()
        /// A cap that overrides every set's share, for tests.
        var limit: Int?
    }

    /// The sequence.
    let program: SequenceProgram
    /// Its indicator's identity, for the log.
    private let id: UUID
    /// The chains.
    private let state = OSAllocatedUnfairLock(uncheckedState: State())

    /// - Parameters:
    ///   - program: The sequence.
    ///   - id: Its indicator's identity, for the log.
    init(_ program: SequenceProgram, id: UUID) {
        self.program = program
        self.id = id
    }

    /// How many chains and early steps it holds now.
    var count: Int { state.withLockUnchecked { $0.chains.waiting.count + $0.chains.early.count } }

    /// How many early steps it holds now.
    var earlySteps: Int { state.withLockUnchecked { $0.chains.early.count } }

    /// How many chains it dropped to stay under its cap.
    var evictions: Int { state.withLockUnchecked { $0.chains.waiting.evictions } }

    /// How many early steps it dropped to stay under their cap.
    var earlyDrops: Int { state.withLockUnchecked { $0.chains.early.evictions } }

    /// How many times the clock went back far enough that it forgot its chains (``SequenceChains/observe(_:)``).
    var clockResets: Int { state.withLockUnchecked { $0.chains.clockResets } }

    /// How long its lines are, its chains' and its early steps' (``SequenceStore/lineLength``).
    var lineLength: Int { state.withLockUnchecked { $0.chains.waiting.lineLength + $0.chains.early.lineLength } }

    /// Cap it whatever set advances it, as a test does to fill it.
    ///
    /// - Parameter capacity: The most chains.
    func limit(to capacity: Int) {
        state.withLockUnchecked { $0.limit = capacity }
    }

    /// Forget every chain, as `macmonitor indicators test` does before each recording.
    func forget() {
        state.withLockUnchecked { $0.chains = SequenceChains() }
    }

    /// Advance the chains an event's matched steps tie into.
    ///
    /// - Parameters:
    ///   - keys: The event's keys.
    ///   - time: When the event happened, in seconds since 2001.
    ///   - capacity: The most chains to hold: the advancing set's share.
    /// - Returns: Did it complete a chain?
    func advance(_ keys: EventKeys, at time: Double, capacity: Int) -> Bool {
        let program = program
        let (completed, evicted, dropped) = state.withLockUnchecked { state -> (Bool, Bool, Bool) in
            let before = (state.chains.waiting.evictions, state.chains.early.evictions)
            let capacity = state.limit ?? capacity
            state.chains.observe(time)
            let completed = program.order == .ordered
                ? state.chains.advanceOrdered(keys, at: time, capacity: capacity, program)
                : state.chains.advanceUnordered(keys, at: time, capacity: capacity, program)
            return (completed, before.0 == 0 && state.chains.waiting.evictions > 0,
                    before.1 == 0 && state.chains.early.evictions > 0)
        }
        if evicted {
            Self.logger.fault("""
                A sequence's chains reached their cap, so the oldest are being dropped. Indicator: \
                \(self.id.uuidString, privacy: .public)
                """)
        }
        if dropped {
            Self.logger.error("""
                A sequence's early steps reached their cap, so the oldest are being dropped, and a step a lane hands \
                over late may miss them. Indicator: \(self.id.uuidString, privacy: .public)
                """)
        }
        return completed
    }
}
