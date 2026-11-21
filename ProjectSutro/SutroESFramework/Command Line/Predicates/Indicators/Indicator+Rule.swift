//
//  Indicator+Rule.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Rules
public extension Indicator {
    /// What an indicator matches: a predicate on one event's record, or a sequence of events whose steps are each such
    /// a predicate.
    enum Rule: Hashable, Sendable {
        /// A predicate on one event's record, as `macmonitor stream --predicate` takes one.
        case event(String)
        /// Several events, each matching a step's predicate, within a time window.
        case sequence(IndicatorSequence)

        /// What an indicator's `kind` says its rule is, as it's saved and as a pack ships it.
        public enum Kind: String, Sendable {
            /// A predicate on one event: what an indicator without a `kind` is.
            case event
            /// A sequence of events.
            case sequence
        }

        /// Its kind.
        public var kind: Kind {
            switch self {
            case .event: .event
            case .sequence: .sequence
            }
        }

        /// Its predicates, each with the step it's for: one, unnamed, for a rule on one event, or each step's, in
        /// order, for a sequence.
        public var predicates: [(step: String?, predicate: String)] {
            switch self {
            case .event(let predicate): [(nil, predicate)]
            case .sequence(let sequence): sequence.steps.map { ($0.name, $0.predicate) }
            }
        }

        /// It as text, for a log or a terminal: the predicate, or a sequence's order, window and keys, then each step
        /// on its own line as its name, its predicate and its joins.
        public var text: String {
            switch self {
            case .event(let predicate):
                return predicate
            case .sequence(let sequence):
                let keys = sequence.by.isEmpty ? "" : " by \(sequence.by.joined(separator: ", "))"
                let count = sequence.atLeast < sequence.steps.count ? ", at least \(sequence.atLeast)" : ""
                let head = "\(sequence.order.rawValue) within \(sequence.within)s\(keys)\(count)"
                return ([head] + sequence.steps.map { step in
                    let joins = step.join.map { " [\($0.field) == \($0.step).\($0.stepField)]" }.joined()
                    return "\(step.name): \(step.predicate)\(joins)"
                }).joined(separator: "\n")
            }
        }
    }

    /// The predicate it matches one event with, or `nil` for a sequence.
    var predicate: String? {
        if case .event(let predicate) = rule { predicate } else { nil }
    }

    /// Its sequence, or `nil` for a rule on one event.
    var sequence: IndicatorSequence? {
        if case .sequence(let sequence) = rule { sequence } else { nil }
    }

    /// The predicate this build matches each event with for it on its own, as `NSPredicate` does: its own, for a rule
    /// on one event this build can run (``isSupported``), and `nil` for one that needs a newer Mac Monitor, or for a
    /// sequence, which only the Security Extension's engine runs (``CompiledIndicators``).
    var eventPredicate: String? {
        isSupported ? predicate : nil
    }

    /// Can this build run it? Only when it names no ``minEngine`` newer than ``engineVersion``. One that can't is kept,
    /// and shown as needing a newer Mac Monitor, but never run.
    var isSupported: Bool {
        minEngine.map { $0 <= Self.engineVersion } ?? true
    }

    /// The Mac Monitor release whose indicator engine this build is. An indicator pack's entry whose `minEngine` is
    /// newer isn't run. It's bumped with every release, which a test checks against the project's version.
    static let engineVersion = ReleaseVersion(3, 2, 0)
}
