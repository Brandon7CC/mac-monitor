//
//  SequenceChains.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Chains
/// A sequence table's chains, waiting for their next steps, and its early steps: later steps that came before the
/// steps they follow (``SequenceTable``).
///
/// Each lane hands its events over in its own order, so a step whose lane isn't the lane of every step before it
/// (``SequenceProgram/arrivesEarly``) can reach the table before or after the step it follows, whatever their times.
/// For such a step, an event that advances no chain is kept as an early step for ``lateness`` seconds, under the key
/// a chain waiting for it would have, and a chain that comes to wait for it takes it then. Up to ``variants`` chains
/// wait for it under one key, and as many early steps are kept, so a step handed over late still finds the chain it
/// follows in time. A step on the lane of every step before it comes in time order, and keeps none of this.
///
/// Chains and early steps are kept until no event a lane may still hand over, ``lateness`` behind the latest, could
/// join them, each in a store of its own, so a burst of early steps never drops a waiting chain.
///
/// **Threading:** none of its own. Its table holds it behind a lock.
struct SequenceChains {
    /// How many seconds behind the latest event it has seen an event must be to mean the clock went back, rather than
    /// a lane handing an event over late: 5 minutes, far past any lane's lag.
    static let clockStep: Double = 300
    /// How many seconds behind the latest event it has seen a lane may hand one over and still have it count: an app's
    /// exec is held up to half a second for Launch Services (``EventHold``), and a lane flooded with events
    /// falls behind the others.
    static let lateness: Double = 10
    /// How many chains may wait under one key for a step that can arrive early, and how many early steps of it are
    /// kept under one key: the latest started, and the latest, which a step handed over late picks among as it would
    /// have in time order.
    static let variants = 4

    /// The chains waiting for their next steps.
    private(set) var waiting = SequenceStore()
    /// The early steps.
    private(set) var early = SequenceStore()
    /// The latest event time it has seen.
    private var latest = -Double.infinity
    /// How many times the clock went back far enough that it forgot every chain (``clockStep``).
    private(set) var clockResets = 0
    /// How many events have advanced an ordered sequence's chains, modulo 2^32: each one's ``Chain/source``.
    private var serial: UInt32 = 0

    /// How many early steps it may keep: a quarter as many as its chains, on top of them, and at least one.
    ///
    /// - Parameter capacity: The most chains it holds.
    /// - Returns: The most early steps.
    static func earlyCapacity(_ capacity: Int) -> Int {
        max(1, capacity / 4)
    }

    /// Note an event's time. One more than ``clockStep`` behind the latest means the clock went back: every chain is
    /// forgotten, as their times are from before the step, and would hold their keys until the clock caught up.
    ///
    /// - Parameter time: The event's time.
    mutating func observe(_ time: Double) {
        guard time < latest - Self.clockStep else {
            latest = max(latest, time)
            return
        }
        waiting.forget()
        early.forget()
        clockResets += 1
        latest = time
    }

    /// When a chain or early step can go: once no event a lane may still hand over can join or take it.
    ///
    /// - Parameters:
    ///   - kind: What its life runs from.
    ///   - program: The sequence.
    /// - Returns: The test.
    private func mortality(_ kind: SequenceStore.Mortality.Kind,
                           _ program: SequenceProgram) -> SequenceStore.Mortality {
        SequenceStore.Mortality(horizon: latest - Self.lateness, within: program.within, kind: kind)
    }

    /// Advance an ordered sequence's chains, from the highest step the event matched down, so it never advances one
    /// chain twice, then start a chain at its first step. A later step that can arrive early is kept as an early step
    /// once every step is done, so the event never takes its own: one that advanced no chain, and one that advanced a
    /// chain short of its last step, as taken, for a chain that started later and comes late.
    ///
    /// - Parameters:
    ///   - keys: The event's keys.
    ///   - time: When it happened.
    ///   - capacity: The most chains to hold.
    ///   - program: The sequence.
    /// - Returns: Did it complete a chain?
    mutating func advanceOrdered(_ keys: EventKeys, at time: Double, capacity: Int,
                                 _ program: SequenceProgram) -> Bool {
        serial &+= 1
        var completed = false, early: UInt8 = 0, takers = SIMD8<Double>(repeating: -.infinity)
        for (position, step) in keys.steps.enumerated() {
            guard step.index > 0 else {
                var chain = Chain(first: time, last: time, by: keys.by)
                chain.source = serial
                remember(step.remembered, in: &chain, program)
                completed = keep(chain, waitingFor: 1, at: time, capacity: capacity, program) || completed
                continue
            }
            guard let (key, found) = waitingChain(for: step, at: time, program) else {
                early |= 1 << position
                continue
            }
            waiting.remove(key)
            guard step.index < program.stepCount - 1 else {
                completed = true
                continue
            }
            var chain = found
            (early, takers[position]) = (early | 1 << position, chain.first)
            chain.last = time
            chain.source = serial
            remember(step.remembered, in: &chain, program)
            completed = keep(chain, waitingFor: step.index + 1, at: time, capacity: capacity, program) || completed
        }
        for (position, step) in keys.steps.enumerated()
        where early & 1 << position != 0 && program.arrivesEarly[step.index] {
            keepEarly(step, by: keys.by, at: time, takenBy: takers[position], capacity: capacity, program)
        }
        return completed
    }

    /// Advance an unordered sequence's chain for the event's `by` key: it completes when a window of
    /// ``SequenceProgram/within`` around the event holds ``SequenceProgram/atLeast`` of its steps, matched by as many
    /// events (``SequenceWindow``).
    ///
    /// - Parameters:
    ///   - keys: The event's keys.
    ///   - time: When it happened.
    ///   - capacity: The most chains to hold.
    ///   - program: The sequence.
    /// - Returns: Did it complete the chain?
    mutating func advanceUnordered(_ keys: EventKeys, at time: Double, capacity: Int,
                                   _ program: SequenceProgram) -> Bool {
        let key = Key(hash: keys.by, step: 0), mortality = mortality(.unordered, program)
        /// An event from more than a window and the lateness before the chain started shares a window with none of
        /// its steps, nor with any event a lane may still hand over.
        if let held = waiting[key], time < held.first - program.within - Self.lateness { return false }
        var chain = waiting.live(at: key, mortality) ?? Chain(first: time, last: time, by: keys.by)
        /// Keep the offsets within a few spans of a window and the lateness, which a `Float` holds to about 16 ms for
        /// a day's window. A step from more than a window before the new base shares no window with an event a lane
        /// may still hand over, and is forgotten.
        let span = program.within + Self.lateness
        if time - chain.first > 2 * span {
            let base = time - span
            chain.times -= SIMD8(repeating: Float(base - chain.first))
            chain.times.replace(with: -.infinity, where: chain.times .< SIMD8(repeating: -Float(program.within)))
            chain.first = base
        }
        chain.eventCount &+= 1
        let offset = Float(time - chain.first)
        var window = SequenceWindow(times: chain.times, events: chain.events, steps: program.stepCount)
        for step in 0..<program.stepCount where keys.mask & 1 << step != 0 {
            window.times[step] = offset
            window.events[step] = chain.eventCount
            if offset >= chain.times[step] {
                chain.times[step] = offset
                chain.events[step] = chain.eventCount
            }
        }
        chain.last = max(chain.last, time)
        guard !window.holds(program.atLeast, around: offset, within: Float(program.within)) else {
            waiting.remove(key)
            return true
        }
        waiting.keep(chain, under: key, capacity: capacity, mortality)
        return false
    }

    /// Can an ordered chain's next step have happened at a time? Not before the step it follows, and not past the
    /// window of its first.
    ///
    /// - Parameters:
    ///   - time: The step's event's time.
    ///   - chain: The chain.
    ///   - program: The sequence.
    /// - Returns: `true` when it can.
    private static func follows(_ time: Double, _ chain: Chain, _ program: SequenceProgram) -> Bool {
        time >= chain.last && time - chain.first <= program.within
    }

    /// How many chains may wait for a step under one key, and how many early steps of it are kept.
    ///
    /// - Parameters:
    ///   - step: The step.
    ///   - program: The sequence.
    /// - Returns: ``variants`` for a step that can arrive early, and 1 otherwise.
    private static func variants(of step: Int, _ program: SequenceProgram) -> Int {
        program.arrivesEarly[step] ? variants : 1
    }

    /// The chain an event's step advances: of those waiting for it under the event's key that it can follow, and that
    /// a later-started chain hadn't taken the key from by its time, the one that started latest, which in time order
    /// would be the one waiting when the event happened.
    ///
    /// - Parameters:
    ///   - step: The step the event matched.
    ///   - time: The event's time.
    ///   - program: The sequence.
    /// - Returns: The chain and its key, or `nil`.
    private mutating func waitingChain(for step: EventKeys.Step, at time: Double,
                                       _ program: SequenceProgram) -> (Key, Chain)? {
        let mortality = mortality(.ordered, program)
        var best: (key: Key, chain: Chain)?
        for variant in 0..<Self.variants(of: step.index, program) {
            let key = Key(hash: step.key, step: step.index, variant: variant)
            guard let chain = waiting.live(at: key, mortality), Self.follows(time, chain, program),
                  time < chain.until else { continue }
            if best.map({ chain.first > $0.chain.first }) ?? true { best = (key, chain) }
        }
        return best
    }

    /// The early step a chain waiting for a step takes: of those kept under its key that follow it, from an event
    /// other than its latest step's, and not taken by a chain that started as late or later, the earliest, which in
    /// time order would have advanced it.
    ///
    /// - Parameters:
    ///   - hash: The chain's key for the step.
    ///   - step: The step.
    ///   - chain: The chain.
    ///   - program: The sequence.
    /// - Returns: The early step and its key, or `nil`.
    private mutating func earlyStep(_ hash: SequenceHash, _ step: Int, following chain: Chain,
                                    _ program: SequenceProgram) -> (Key, Chain)? {
        guard program.arrivesEarly[step], !early.isEmpty else { return nil }
        let mortality = mortality(.early, program)
        var best: (key: Key, chain: Chain)?
        for variant in 0..<Self.variants {
            let key = Key(hash: hash, step: step, variant: variant)
            guard let next = early.live(at: key, mortality), next.source != chain.source,
                  chain.first > next.takenBy, Self.follows(next.first, chain, program) else { continue }
            if best.map({ next.first < $0.chain.first }) ?? true { best = (key, next) }
        }
        return best
    }

    /// Put a step's values for later joins in a chain's slots.
    ///
    /// - Parameters:
    ///   - remembered: The values, by slot.
    ///   - chain: The chain.
    ///   - program: The sequence.
    private func remember(_ remembered: some Collection<(slot: Int, hash: SequenceHash)>, in chain: inout Chain,
                          _ program: SequenceProgram) {
        guard !remembered.isEmpty else { return }
        if chain.slots == nil {
            chain.slots = ContiguousArray(repeating: SequenceHash(low: 0, high: 0), count: program.slotCount)
        }
        for (slot, hash) in remembered { chain.slots?[slot] = hash }
    }

    /// Keep an ordered chain waiting for a step, under the key that step's event will have, after taking each early
    /// step that follows it. An early step it takes short of the last is kept, as taken by it, for a chain that
    /// started later and comes late.
    ///
    /// - Parameters:
    ///   - chain: The chain.
    ///   - step: The step it waits for.
    ///   - time: The event's time.
    ///   - capacity: The most chains to hold.
    ///   - program: The sequence.
    /// - Returns: Did early steps complete it?
    private mutating func keep(_ chain: Chain, waitingFor step: Int, at time: Double, capacity: Int,
                               _ program: SequenceProgram) -> Bool {
        var chain = chain, step = step
        while true {
            let hash = program.key(by: chain.by, slots: chain.slots, waitingFor: step)
            if let (key, next) = earlyStep(hash, step, following: chain, program) {
                guard step < program.stepCount - 1 else {
                    early.remove(key)
                    return true
                }
                early.update(key) { $0.takenBy = chain.first }
                chain.last = next.first
                chain.source = next.source
                if let slots = next.slots {
                    let kept = program.remembers[step].lazy.map { (slot: $0.slot, hash: slots[$0.slot]) }
                    remember(kept, in: &chain, program)
                }
                step += 1
                continue
            }
            if !program.keepsSlots[step] { chain.slots = nil }
            wait(chain, for: step, under: hash, capacity: capacity, program)
            return false
        }
    }

    /// Keep a chain waiting for a step. Of two chains waiting for one step under one key, the one that started later
    /// takes the key once both have come, in time order, as its window ends later: the other advances only with an
    /// event from before then (``Chain/until``), and one that can't is dropped. One chain waits under a key for a step
    /// that comes in time order, and up to ``variants`` for one that can arrive early, so a step handed over late can
    /// still advance the chain it follows in time.
    ///
    /// - Parameters:
    ///   - chain: The chain.
    ///   - step: The step it waits for.
    ///   - hash: Its key for the step.
    ///   - capacity: The most chains to hold.
    ///   - program: The sequence.
    private mutating func wait(_ chain: Chain, for step: Int, under hash: SequenceHash, capacity: Int,
                               _ program: SequenceProgram) {
        let mortality = mortality(.ordered, program)
        var chain = chain, free: Key?, oldest: (key: Key, first: Double)?
        chain.until = .infinity
        for variant in 0..<Self.variants(of: step, program) {
            let key = Key(hash: hash, step: step, variant: variant)
            guard var held = waiting.live(at: key, mortality) else {
                free = free ?? key
                continue
            }
            if chain.first >= held.first {
                held.until = min(held.until, max(held.last, chain.last))
                guard held.until > held.last else {
                    waiting.remove(key)
                    free = free ?? key
                    continue
                }
                waiting.update(key) { $0.until = held.until }
            } else {
                chain.until = min(chain.until, max(chain.last, held.last))
            }
            if oldest.map({ held.first < $0.first }) ?? true { oldest = (key, held.first) }
        }
        guard chain.until > chain.last,
              let target = free ?? oldest.flatMap({ chain.first >= $0.first ? $0.key : nil }) else { return }
        waiting.keep(chain, under: target, capacity: capacity, mortality)
    }

    /// Keep a step for a chain whose earlier steps a lane behind still has. Under one key the latest ``variants``
    /// stay: a chain that comes late takes the earliest that follows it.
    ///
    /// - Parameters:
    ///   - step: The step.
    ///   - by: The event's `by` values' hash.
    ///   - time: The event's time.
    ///   - takenBy: When the chain it advanced started, or minus infinity for none.
    ///   - capacity: The most chains to hold, a quarter of which is the most early steps.
    ///   - program: The sequence.
    private mutating func keepEarly(_ step: EventKeys.Step, by: SequenceHash, at time: Double, takenBy: Double,
                                    capacity: Int, _ program: SequenceProgram) {
        let mortality = mortality(.early, program)
        var target: Key?, earliest = Double.infinity
        for variant in 0..<Self.variants {
            let key = Key(hash: step.key, step: step.index, variant: variant)
            guard let kept = early.live(at: key, mortality) else {
                (target, earliest) = (key, -.infinity)
                break
            }
            if kept.first < earliest { (target, earliest) = (key, kept.first) }
        }
        guard let target, time >= earliest else { return }
        var entry = Chain(first: time, last: time, by: by)
        (entry.source, entry.takenBy) = (serial, takenBy)
        remember(step.remembered, in: &entry, program)
        early.keep(entry, under: target, capacity: Self.earlyCapacity(capacity), mortality)
    }
}
