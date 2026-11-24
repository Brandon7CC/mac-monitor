//
//  IndicatorSequence+Validation.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation


// MARK: - Limits
public extension IndicatorSequence {
    /// What a sequence may be, as the indicators repository's linter and its pack schema allow.
    enum Limits {
        /// How many steps it has.
        public static let steps = 2...8
        /// How many seconds its window is: a second to a day.
        public static let within = 1...86_400
        /// What a step's name looks like.
        public static let stepName = #"^[a-z][a-z0-9_]*$"#
        /// How many key paths `by` names, each once: every one is read and hashed for each event that matches a step.
        public static let byPaths = 8
        /// How many joins a step has, each once.
        public static let joins = 8
        /// How many distinct earlier fields its joins read, over every step: each is a value a chain keeps, 16 bytes
        /// apiece, for a later step.
        public static let joinedFields = 16
    }

    /// Why it can't be used, or `nil` when it can: its shape, as ``shapeProblem`` checks it, then each step's
    /// predicate, as a rule on one event's is checked (``Indicator/problem``).
    var problem: String? {
        shapeProblem ?? steps.lazy.compactMap { step in
            Indicator.problem(with: step.predicate).map { "The step \(step.name): \($0)" }
        }.first
    }

    /// Why the Security Extension can't run it, or `nil` when it can: its shape, then each step's predicate, as the
    /// Security Extension compiles a rule on one event's (``IndicatorCompiler``).
    var sensorProblem: String? {
        shapeProblem ?? steps.lazy.compactMap { step in
            IndicatorCompiler.problem(with: step.predicate).map { "The step \(step.name): \($0.description)" }
        }.first
    }

    /// Why its steps, window and keys don't make a sequence, or `nil` when they do. It has 2 to 8 steps, each named
    /// once, a window of a second to a day, and every step tied to the others: an unordered sequence by its `by` keys,
    /// an ordered one by them or by each later step's joins to steps before it. An ordered sequence needs every step.
    /// `by` and each step's joins are short lists without repeats (``Limits``), so a sequence's work for each event and
    /// its chains' memory stay small.
    var shapeProblem: String? {
        guard Limits.steps.contains(steps.count) else {
            return "A sequence has \(Limits.steps.lowerBound) to \(Limits.steps.upperBound) steps, not \(steps.count)."
        }
        guard Limits.within.contains(within) else {
            return "Its window, within, is a second to a day, not \(within) seconds."
        }
        guard by.count <= Limits.byPaths else {
            return "by names at most \(Limits.byPaths) key paths, not \(by.count)."
        }
        guard Set(by).count == by.count else { return "by names a key path twice." }
        let joined = Set(steps.flatMap { $0.join.map { "\($0.step) \($0.stepField)" } })
        guard joined.count <= Limits.joinedFields else {
            return "The joins read at most \(Limits.joinedFields) fields of earlier steps, not \(joined.count)."
        }
        if let problem = stepsProblem ?? by.lazy.compactMap(Self.keyPathProblem).first { return problem }
        if order == .unordered, by.isEmpty {
            return "An unordered sequence needs by: the key paths every step's event shares."
        }
        guard (Limits.steps.lowerBound...steps.count).contains(atLeast) else {
            return "atLeast is from \(Limits.steps.lowerBound) to its \(steps.count) steps, not \(atLeast)."
        }
        if order == .ordered, atLeast != steps.count {
            return "An ordered sequence needs every step: atLeast must be \(steps.count), not \(atLeast)."
        }
        return nil
    }

    /// Why a step's name or joins are wrong, or `nil` when every step's are right.
    private var stepsProblem: String? {
        var earlier: Set<String> = []
        for (index, step) in steps.enumerated() {
            guard step.name.range(of: Limits.stepName, options: .regularExpression) != nil else {
                return "The step name '\(step.name)' must be a lowercase letter, then lowercase letters, digits "
                    + "and underscores."
            }
            guard !earlier.contains(step.name) else { return "Two steps are named \(step.name)." }
            if order == .unordered, !step.join.isEmpty {
                return "The step \(step.name) joins, but only an ordered sequence's steps do. Tie it with by."
            }
            guard step.join.count <= Limits.joins else {
                return "The step \(step.name) has at most \(Limits.joins) joins, not \(step.join.count)."
            }
            guard Set(step.join).count == step.join.count else { return "The step \(step.name) has a join twice." }
            for join in step.join {
                guard earlier.contains(join.step) else {
                    return "The step \(step.name) joins \(join.step), which isn't a step before it."
                }
                if let problem = Self.keyPathProblem(join.field) ?? Self.keyPathProblem(join.stepField) {
                    return "The step \(step.name)'s join: \(problem)"
                }
            }
            if order == .ordered, index > 0, step.join.isEmpty, by.isEmpty {
                return "Nothing ties the step \(step.name) to the steps before it: give it a join, or the sequence by."
            }
            earlier.insert(step.name)
        }
        return nil
    }

    /// Why a key path can't be compared, or `nil` when it can.
    ///
    /// - Parameter path: A record's key path, as `by` or a join names one.
    /// - Returns: The reason, such as a key the telemetry schema doesn't have.
    private static func keyPathProblem(_ path: String) -> String? {
        do {
            _ = try IndicatorField.record(path)
            return nil
        } catch {
            return error.description
        }
    }
}
