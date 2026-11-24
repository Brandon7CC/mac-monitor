//
//  IndicatorSequence.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Sequences
/// An indicator's rule whose evidence is several events: steps, each a predicate on one event's record, that must
/// match within a time window, tied together by values their events share. Only the event that completes the chain is
/// tagged, never the earlier steps'. The indicators repository writes one as `steps` in its YAML, and a pack ships it
/// as an indicator of `kind` `sequence`:
///
/// ```json
/// { "kind": "sequence", "sequence": { "order": "ordered", "within": 5, "by": [], "atLeast": 2, "steps": [
///   { "name": "download", "predicate": "...", "join": [] },
///   { "name": "executable", "predicate": "...",
///     "join": [ { "field": "target_path", "step": "download", "stepField": "target_path" } ] } ] } }
/// ```
public struct IndicatorSequence: Codable, Hashable, Sendable {
    /// Whether the steps must match in the order they're listed.
    public enum Order: String, Codable, Sendable {
        /// The steps in the listed order, by event time.
        case ordered
        /// The steps in any order.
        case unordered
    }

    /// A field of a step's event that must equal a field of the event an earlier step matched, for a chain whose key
    /// changes from step to step, such as a file a download wrote and then ran.
    public struct Join: Codable, Hashable, Sendable {
        /// The key path on this step's event, such as `target_path`.
        public var field: String
        /// The earlier step's name.
        public var step: String
        /// The key path on the earlier step's event.
        public var stepField: String

        /// - Parameters:
        ///   - field: The key path on this step's event.
        ///   - step: The earlier step's name.
        ///   - stepField: The key path on the earlier step's event.
        public init(field: String, step: String, stepField: String) {
            (self.field, self.step, self.stepField) = (field, step, stepField)
        }
    }

    /// One event of the chain.
    public struct Step: Codable, Hashable, Sendable {
        /// What it's called, such as `download`: a lowercase letter, then lowercase letters, digits and underscores.
        public var name: String
        /// The predicate its event matches, as a rule on one event takes one.
        public var predicate: String
        /// The fields its event shares with earlier steps' events. Only an ordered sequence's steps have any.
        public var join: [Join]

        /// - Parameters:
        ///   - name: What it's called.
        ///   - predicate: The predicate its event matches.
        ///   - join: The fields its event shares with earlier steps' events.
        public init(name: String, predicate: String, join: [Join] = []) {
            (self.name, self.predicate, self.join) = (name, predicate, join)
        }

        /// Decode a step. One without `join` joins nothing.
        ///
        /// - Parameter decoder: The decoder.
        /// - Throws: When its name or predicate is missing, or a key isn't what it should be.
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            name = try container.decode(String.self, forKey: .name)
            predicate = try container.decode(String.self, forKey: .predicate)
            join = try container.decodeIfPresent([Join].self, forKey: .join) ?? []
        }
    }

    /// Whether the steps must match in their order.
    public var order: Order
    /// The most seconds from the first step's event to the last's.
    public var within: Int
    /// The key paths whose values every step's event must share, such as a process's audit token's `pid` and
    /// `pidversion`, which together name one process.
    public var by: [String]
    /// How many of the steps must match: all of them for an ordered sequence.
    public var atLeast: Int
    /// The steps, in their order.
    public var steps: [Step]

    /// - Parameters:
    ///   - order: Whether the steps must match in their order.
    ///   - within: The most seconds from the first step's event to the last's.
    ///   - by: The key paths whose values every step's event must share.
    ///   - atLeast: How many steps must match, or `nil` for all of them.
    ///   - steps: The steps.
    public init(order: Order, within: Int, by: [String] = [], atLeast: Int? = nil, steps: [Step]) {
        (self.order, self.within, self.by, self.steps) = (order, within, by, steps)
        self.atLeast = atLeast ?? steps.count
    }

    /// Decode a sequence. One without `by` shares no key, and one without `atLeast` needs every step.
    ///
    /// - Parameter decoder: The decoder.
    /// - Throws: When its order, window or steps are missing, or a key isn't what it should be.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        order = try container.decode(Order.self, forKey: .order)
        within = try container.decode(Int.self, forKey: .within)
        by = try container.decodeIfPresent([String].self, forKey: .by) ?? []
        steps = try container.decode([Step].self, forKey: .steps)
        atLeast = try container.decodeIfPresent(Int.self, forKey: .atLeast) ?? steps.count
    }
}
