//
//  CompiledIndicators+Building.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/15/26.
//

import Foundation
import EndpointSecurity


// MARK: - Building a set
extension CompiledIndicators {
    /// What compiling a set makes of its indicators, one at a time, before its programs are frozen: each rule's
    /// program, hit and types, and each sequence's steps, which are rules too, and its table.
    struct Builder {
        /// The indicators Mac Monitor ships, by identity.
        let defaults: [UUID: Indicator]
        /// The indicator pack those are, or 0 for a build's own.
        let pack: Int
        /// The set whose compiled predicates and sequence tables to reuse.
        let previous: CompiledIndicators?
        /// Every predicate compiled, by its text's bytes.
        var compiled: [Source: Compiled] = [:]
        /// Where each program comes from, by its index.
        var origins: [FrozenPrograms.Origin] = []
        /// Each rule's program.
        var rules: [Int32] = []
        /// Each rule's hit: a step's is its sequence's.
        var ruleHits = ContiguousArray<IndicatorHit>()
        /// Each rule's step (``CompiledIndicators/stepRule(sequence:step:)``), or -1 for a rule of its own.
        var ruleSteps = ContiguousArray<Int32>()
        /// The rules for each event type, by the type's number: Mac Monitor's own events' too.
        var byType = [[Int32]](repeating: [], count: MacMonitorEvent.typeLimit)
        /// The indicators it can't run.
        var problems: [Problem] = []
        /// The sequences it runs.
        var sequences: [CompiledSequence] = []
        /// How many predicates it compiled rather than reused.
        var compiledCount = 0

        /// - Parameters:
        ///   - defaults: The indicators Mac Monitor ships, by identity.
        ///   - pack: The indicator pack those are, or 0 for a build's own.
        ///   - previous: The set to reuse.
        ///   - capacity: How many indicators it will have.
        init(defaults: [UUID: Indicator], pack: Int, previous: CompiledIndicators?, capacity: Int) {
            (self.defaults, self.pack, self.previous) = (defaults, pack, previous)
            compiled.reserveCapacity(capacity)
        }

        /// Add an indicator: a rule on one event, a sequence, or a problem.
        ///
        /// - Parameter indicator: The indicator. One that's off isn't run, but its problems are listed.
        mutating func add(_ indicator: Indicator) {
            guard indicator.isSupported else {
                if let reason = indicator.sensorProblem {
                    problems.append(Problem(id: indicator.id, problem: .unreadable(reason)))
                }
                return
            }
            switch indicator.rule {
            case .event(let predicate): addRule(indicator, predicate)
            case .sequence(let sequence): addSequence(indicator, sequence)
            }
        }

        /// - Parameters:
        ///   - indicator: An indicator on one event.
        ///   - predicate: Its predicate.
        private mutating func addRule(_ indicator: Indicator, _ predicate: String) {
            switch entry(for: predicate) {
            case .problem(let problem):
                problems.append(Problem(id: indicator.id, problem: problem))
            case .rule(let types, let program) where indicator.isEnabled:
                append(program, types: types, hit: IndicatorHit(indicator, against: defaults, pack: pack,
                                                                evaluatedBy: .securityExtension), step: -1)
            case .rule:
                return
            }
        }

        /// Compile a sequence's steps as rules, each hitting nothing alone, and give it a table: the previous set's
        /// when the sequence is the same, so its open chains carry over.
        ///
        /// - Parameters:
        ///   - indicator: A sequence's indicator.
        ///   - sequence: Its sequence.
        private mutating func addSequence(_ indicator: Indicator, _ sequence: IndicatorSequence) {
            if let problem = sequence.shapeProblem {
                return problems.append(Problem(id: indicator.id, problem: .unreadable(problem)))
            }
            var steps: [(types: [Int], program: Int32)] = []
            for step in sequence.steps {
                switch entry(for: step.predicate) {
                case .rule(let types, let program):
                    steps.append((types, program))
                case .problem(let problem):
                    let reason = SensorProblem.unreadable("The step \(step.name): \(problem.description)")
                    return problems.append(Problem(id: indicator.id, problem: reason))
                }
            }
            let program: SequenceProgram
            do throws(SensorProblem) {
                program = try SequenceProgram(sequence, types: steps.map(\.types))
            } catch {
                return problems.append(Problem(id: indicator.id, problem: error))
            }
            guard indicator.isEnabled else { return }
            let hit = IndicatorHit(indicator, against: defaults, pack: pack, evaluatedBy: .securityExtension)
            let index = sequences.count, position = Int32(rules.count)
            for (number, step) in steps.enumerated() {
                append(step.program, types: step.types, hit: hit,
                       step: CompiledIndicators.stepRule(sequence: index, step: number))
            }
            let table = previous?.sequences.first { $0.id == indicator.id && $0.sequence == sequence }?.table
                ?? SequenceTable(program, id: indicator.id)
            sequences.append(CompiledSequence(id: indicator.id, sequence: sequence, table: table, hit: hit,
                                              position: position))
        }

        /// - Parameters:
        ///   - program: A rule's program.
        ///   - types: The event types it runs on.
        ///   - hit: Its hit.
        ///   - step: Its step, or -1.
        private mutating func append(_ program: Int32, types: [Int], hit: IndicatorHit, step: Int32) {
            let index = Int32(rules.count)
            rules.append(program)
            ruleHits.append(hit)
            ruleSteps.append(step)
            for type in types where byType.indices.contains(type) { byType[type].append(index) }
        }

        /// A predicate's program or problem: this set's, the previous set's, or compiled now.
        ///
        /// - Parameter predicate: The predicate.
        /// - Returns: What it compiled to.
        private mutating func entry(for predicate: String) -> Compiled {
            let source = Source(predicate)
            if let known = compiled[source] { return known }
            let entry: Compiled
            if let previous, let known = previous.compiled[source] {
                if case .rule(let types, let program) = known {
                    entry = .rule(types: types, program: Int32(origins.count))
                    origins.append(.frozen(previous.frozen, Int(program)))
                } else {
                    entry = known
                }
            } else {
                compiledCount += 1
                switch IndicatorCompiler.compile(source.text) {
                case .success(let rule):
                    entry = .rule(types: rule.types, program: Int32(origins.count))
                    origins.append(.compiled(rule.program))
                case .failure(let problem):
                    entry = .problem(problem)
                }
            }
            compiled[source] = entry
            return entry
        }
    }
}
