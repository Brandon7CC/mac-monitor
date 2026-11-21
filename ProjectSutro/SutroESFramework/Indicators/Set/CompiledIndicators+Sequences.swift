//
//  CompiledIndicators+Sequences.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Sequences a set runs
/// A sequence a set runs: its steps are the set's rules, and the set's own open chains for it are in its table.
struct CompiledSequence {
    /// Its indicator's identity.
    let id: UUID
    /// The sequence, which a set made from this one compares to keep its table.
    let sequence: IndicatorSequence
    /// The set's own open chains for it (``CompiledIndicators/chains``).
    let table: SequenceTable
    /// Its hit, which the event that completes a chain gets.
    let hit: IndicatorHit
    /// Its place in the set's order: its first step's rule.
    let position: Int32
}


// MARK: - Evaluating sequences
/// A sequence's steps are rules like any other: an event is evaluated against those of its type that the index picks,
/// in the same scan. A step that matches tags nothing. Once the scan is done, each sequence whose steps the event
/// matched reads the event's `by` and join values (``EventKeys``) and advances its chains (``SequenceTable``), and
/// one it completes adds the sequence's hit, in the set's order. A step left undetermined lists its sequence as
/// undetermined, once for the event.
///
/// The exec lane defers its events' steps to their turn to be sent (``advance(_:steps:values:chains:)``), so an app's
/// exec held for Launch Services advances its sequences with the launched-by parent it leaves with, and the events
/// behind it advance them after it, in Endpoint Security's order (``LaunchServicesHold``).
extension CompiledIndicators {
    /// A step's rule as ``ruleSteps`` keeps it: its sequence's index, then its own in the low 3 bits.
    ///
    /// - Parameters:
    ///   - sequence: The sequence's index in ``sequences``.
    ///   - step: The step's, under 8.
    /// - Returns: The step.
    static func stepRule(sequence: Int, step: Int) -> Int32 {
        Int32(sequence << 3 | step)
    }

    /// Advance the sequences whose steps an event matched, and add a hit for each chain it completed.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - values: The lane's values for this event, holding the steps it matched in the set's order.
    ///   - chains: The chains to advance.
    ///   - capped: Was the event counted already as matching more than ``hitLimit``?
    ///   - result: The event's evaluation.
    func advanceSequences(_ message: borrowing Message, values: inout MessageValueCache, chains: SessionChains,
                          capped: Bool, into result: inout IndicatorEvaluation) {
        let matches = values.takeStepMatches()
        defer { values.returnStepMatches(matches) }
        advanceSequences(message, matches: matches, values: &values, chains: chains, capped: capped, into: &result)
    }

    /// Advance the sequences whose steps an event matched, once it's the event's turn, and add the hit of each chain
    /// it completes to its verdicts, in the set's order.
    ///
    /// - Parameters:
    ///   - message: The event, stamped with ``stamp(_:values:chains:deferringSteps:)`` deferring its steps.
    ///   - steps: The steps that stamp handed back.
    ///   - values: The values of the lane advancing it.
    ///   - chains: The capture session's chains, or `nil` for the set's own: a session always passes its own.
    func advance(_ message: inout Message, steps: ContiguousArray<Int32>, values: inout MessageValueCache,
                 chains: SessionChains?) {
        guard !steps.isEmpty else { return }
        values.reset()
        defer { values.reset() }
        values.recordPaths = recordPaths
        var result = IndicatorEvaluation(hits: message.indicators?.hits ?? [])
        /// Its stamp counted it if its scan found more hits than a record lists, which leaves it full.
        advanceSequences(message, matches: steps, values: &values, chains: chains ?? self.chains,
                         capped: result.hits.count >= Self.hitLimit, into: &result)
        message.indicators = IndicatorVerdicts(result.hits)
    }

    /// Every sequence whose steps the event matched advances, a record full of hits or not: one whose hit doesn't fit
    /// only loses its hit, and the event is counted once as matching more than ``hitLimit``.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - matches: The steps it matched, in the set's order.
    ///   - values: The lane's values for this event.
    ///   - chains: The chains to advance, one table for each of the set's sequences.
    ///   - capped: Was the event counted already as matching more than ``hitLimit``?
    ///   - result: The event's evaluation.
    private func advanceSequences(_ message: borrowing Message, matches: ContiguousArray<Int32>,
                                  values: inout MessageValueCache, chains: SessionChains, capped: Bool,
                                  into result: inout IndicatorEvaluation) {
        var capped = capped
        let time = message.message_darwin_time.timeIntervalSinceReferenceDate
        var start = 0
        while start < matches.count {
            let index = Int(matches[start] >> 3)
            var mask: UInt8 = 0, end = start
            let first = start
            while end < matches.count, Int(matches[end] >> 3) == index {
                mask |= 1 << UInt8(matches[end] & 7)
                end += 1
            }
            start = end
            let sequence = sequences[index], table = chains.tables[index]
            guard let keys = EventKeys(table.program, mask: mask, message, values: &values),
                  table.advance(keys, at: time, capacity: chains.share) else { continue }
            var hit = sequence.hit
            /// The steps this event matched, which completed the chain.
            let roots = matches[first..<end].compactMap { stepRoots[$0] }
            hit.matched = matched(roots: roots, message, type: Self.eventType(of: message), values: &values)
            guard add(hit, at: sequence.position, to: &result.hits) else {
                if !capped { noteCapped(message, values: &values) }
                capped = true
                continue
            }
        }
    }

    /// Put a hit among an event's others in the set's order.
    ///
    /// - Parameters:
    ///   - hit: The hit.
    ///   - position: Its indicator's place in the set.
    ///   - hits: The event's hits.
    /// - Returns: `false` when they're at ``hitLimit``, and it wasn't added.
    func add(_ hit: IndicatorHit, at position: Int32, to hits: inout [IndicatorHit]) -> Bool {
        guard hits.count < Self.hitLimit else { return false }
        let at = hits.firstIndex { positions[$0.id, default: .max] > position } ?? hits.endIndex
        hits.insert(hit, at: at)
        return true
    }

    /// Forget the set's own open chains, as `macmonitor indicators test` does before each recording, so one
    /// recording's steps never complete another's.
    func forgetChains() {
        for table in chains.tables { table.forget() }
    }

    /// How many chains and early steps the set's own tables hold now, for tests and the benchmarks.
    var openChains: Int { chains.openChains }
}


// MARK: - An event's step matches
extension MessageValueCache {
    /// Did this event match a sequence's step?
    var hasStepMatches: Bool { !stepMatches.isEmpty }

    /// Note a sequence step the event matched.
    ///
    /// - Parameter step: The step's rule (``CompiledIndicators/stepRule(sequence:step:)``).
    @inline(__always)
    mutating func noteStep(_ step: Int32) {
        stepMatches.append(step)
    }

    /// Take the steps this event matched, so its values can be read while they're walked. Give them back with
    /// ``returnStepMatches(_:)``, which empties them for the next event.
    ///
    /// - Returns: The steps, in the set's order.
    mutating func takeStepMatches() -> ContiguousArray<Int32> {
        var taken = ContiguousArray<Int32>()
        swap(&taken, &stepMatches)
        return taken
    }

    /// Give back, emptied, the steps ``takeStepMatches()`` took.
    ///
    /// - Parameter steps: The steps.
    mutating func returnStepMatches(_ steps: consuming ContiguousArray<Int32>) {
        var steps = steps
        steps.removeAll(keepingCapacity: true)
        stepMatches = steps
    }
}
