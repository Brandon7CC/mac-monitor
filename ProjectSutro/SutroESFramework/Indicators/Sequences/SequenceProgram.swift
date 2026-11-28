//
//  SequenceProgram.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation
import EndpointSecurity


// MARK: - Sequence programs
/// What the Security Extension needs of a sequence (``IndicatorSequence``) beyond its steps' rules, which compile as
/// any rule on one event does: the fields that tie its steps, read from each step's event, and where a chain keeps the
/// values later steps join to.
///
/// A join is `field == step.stepField`: a field of this step's event equal to a field of the event that matched an
/// earlier step. Each distinct earlier step and field is one slot, which a chain fills with the value's hash
/// (``SequenceHash``) when that step matches, so the step that joins to it can be looked up by its own values.
struct SequenceProgram: Sendable {
    /// One field of a step's event, and the slot its value goes in or is compared with.
    struct Slotted: Sendable, Equatable {
        /// The field.
        let field: IndicatorField
        /// The slot.
        let slot: Int
    }

    /// Whether its steps happen in order.
    let order: IndicatorSequence.Order
    /// The most seconds from its first step to its last.
    let within: Double
    /// How many of its steps make a match: all of an ordered sequence's.
    let atLeast: Int
    /// How many steps it has.
    let stepCount: Int
    /// The fields every step's event shares.
    let by: [IndicatorField]
    /// Each step's joins: the field of its event, and the slot of the earlier value it equals, in the joins' order.
    let joins: [[Slotted]]
    /// Each step's fields that later steps join to, and the slot each value goes in.
    let remembers: [[Slotted]]
    /// How many slots a chain has.
    let slotCount: Int
    /// For a chain waiting for each step, whether a step after it still joins to a slot. One that doesn't lets its
    /// slots go.
    let keepsSlots: [Bool]
    /// For each step, whether its event can reach the table before the event of a step before it: when the steps up
    /// to it run on more than one lane (``EventClass``), each of which hands its events over in its own order. One
    /// lane hands over in Endpoint Security's order, its app execs held for Launch Services included
    /// (``EventHold``), so a step on the lane of every step before it never comes early.
    let arrivesEarly: [Bool]

    /// - Parameters:
    ///   - sequence: A sequence with no ``IndicatorSequence/shapeProblem``.
    ///   - types: The event types each step's rule runs on, in order. Without them, every later step can arrive
    ///     early.
    /// - Throws: ``SensorProblem`` for a `by` or join key path an event's record doesn't have, which a sequence with no
    ///   shape problem never has.
    init(_ sequence: IndicatorSequence, types: [[Int]] = []) throws(SensorProblem) {
        order = sequence.order
        within = Double(sequence.within)
        atLeast = sequence.order == .ordered ? sequence.steps.count : sequence.atLeast
        stepCount = sequence.steps.count
        by = try sequence.by.map { path throws(SensorProblem) in try IndicatorField.record(path) }
        let names = Dictionary(sequence.steps.enumerated().map { ($1.name, $0) }) { first, _ in first }
        var slots: [String: Int] = [:]
        var joins: [[Slotted]] = [], remembers = [[Slotted]](repeating: [], count: sequence.steps.count)
        for step in sequence.steps {
            var stepJoins: [Slotted] = []
            for join in step.join {
                guard let earlier = names[join.step] else { throw .unreadable("No step is named \(join.step).") }
                let key = "\(earlier) \(join.stepField)"
                let slot: Int
                if let known = slots[key] {
                    slot = known
                } else {
                    slot = slots.count
                    slots[key] = slot
                    remembers[earlier].append(Slotted(field: try IndicatorField.record(join.stepField), slot: slot))
                }
                stepJoins.append(Slotted(field: try IndicatorField.record(join.field), slot: slot))
            }
            joins.append(stepJoins)
        }
        self.joins = joins
        self.remembers = remembers
        slotCount = slots.count
        keepsSlots = joins.indices.map { waiting in joins.dropFirst(waiting + 1).contains { !$0.isEmpty } }
        let lanes = types.map { Set($0.map { EventClassTable.eventClass(of: es_event_type_t(UInt32(clamping: $0))) }) }
        arrivesEarly = sequence.steps.indices.map { step in
            guard step > 0 else { return false }
            guard lanes.count == sequence.steps.count else { return true }
            return lanes[...step].reduce(into: Set<EventClass>()) { $0.formUnion($1) }.count > 1
        }
    }

    /// Every field its steps' events are read for: what the set's record walk must find.
    var fields: [IndicatorField] {
        by + joins.joined().map(\.field) + remembers.joined().map(\.field)
    }

    /// The key a chain waiting for a step is kept under, from the values it holds, which is the key that step's event
    /// looks it up by (``EventKeys``).
    ///
    /// - Parameters:
    ///   - by: The chain's `by` values' hash.
    ///   - slots: Its slots.
    ///   - step: The step it waits for.
    /// - Returns: The key.
    func key(by: SequenceHash, slots: ContiguousArray<SequenceHash>?, waitingFor step: Int) -> SequenceHash {
        var hasher = SequenceHasher()
        hasher.combine(by)
        if let slots { for join in joins[step] { hasher.combine(slots[join.slot]) } }
        return hasher.finalize()
    }
}


// MARK: - An event's keys
/// What a sequence needs from an event that matched some of its steps, read before its chains are locked: the
/// event's `by` values' hash, and for each step it matched, the key it looks a chain up by and the values later
/// steps join to.
struct EventKeys {
    /// One step the event matched.
    struct Step {
        /// The step's index.
        let index: Int
        /// The key of a chain waiting for this step: the `by` hash and the event's join values.
        let key: SequenceHash
        /// The values later steps join to, by slot.
        let remembered: [(slot: Int, hash: SequenceHash)]
    }

    /// The event's `by` values' hash.
    let by: SequenceHash
    /// The steps it matched that it has every value of, highest first, so an event that matched two steps can't
    /// advance one chain twice.
    let steps: [Step]
    /// The steps it matched, by bit.
    let mask: UInt8

    /// Read an event's keys.
    ///
    /// - Parameters:
    ///   - program: The sequence.
    ///   - mask: The steps the event matched, by bit.
    ///   - message: The event.
    ///   - values: The lane's values for this event.
    /// - Returns: The keys, or `nil` when the event is missing a `by` value or every step's join values, so it ties
    ///   nothing.
    init?(_ program: SequenceProgram, mask: UInt8, _ message: borrowing Message, values: inout MessageValueCache) {
        var hasher = SequenceHasher()
        for field in program.by where !hasher.combine(values.value(of: field, in: message)) { return nil }
        by = hasher.finalize()
        guard program.order == .ordered else {
            (steps, self.mask) = ([], mask)
            return
        }
        var steps: [Step] = []
        for index in stride(from: program.stepCount - 1, through: 0, by: -1) where mask & 1 << index != 0 {
            guard let step = Self.step(index, of: program, by: by, message, values: &values) else { continue }
            steps.append(step)
        }
        guard !steps.isEmpty else { return nil }
        (self.steps, self.mask) = (steps, mask)
    }

    /// - Parameters:
    ///   - index: A step the event matched.
    ///   - program: The sequence.
    ///   - by: The event's `by` hash.
    ///   - message: The event.
    ///   - values: The lane's values for this event.
    /// - Returns: Its key and remembered values, or `nil` when the event is missing one of them.
    private static func step(_ index: Int, of program: SequenceProgram, by: SequenceHash, _ message: borrowing Message,
                             values: inout MessageValueCache) -> Step? {
        var key = SequenceHasher()
        key.combine(by)
        for join in program.joins[index] {
            guard let hash = hash(of: join.field, message, &values) else { return nil }
            key.combine(hash)
        }
        var remembered: [(slot: Int, hash: SequenceHash)] = []
        for kept in program.remembers[index] {
            guard let hash = hash(of: kept.field, message, &values) else { return nil }
            remembered.append((kept.slot, hash))
        }
        return Step(index: index, key: key.finalize(), remembered: remembered)
    }

    /// - Parameters:
    ///   - field: A field.
    ///   - message: The event.
    ///   - values: The lane's values for this event.
    /// - Returns: Its value's hash, or `nil` when it's missing.
    private static func hash(of field: IndicatorField, _ message: borrowing Message,
                             _ values: inout MessageValueCache) -> SequenceHash? {
        var hasher = SequenceHasher()
        return hasher.combine(values.value(of: field, in: message)) ? hasher.finalize() : nil
    }
}
