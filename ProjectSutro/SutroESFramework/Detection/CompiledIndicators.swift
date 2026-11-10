//
//  CompiledIndicators.swift
//  SutroESFramework
//
//  Created by Brandon Dalton on 11/8/26.
//

import Foundation
import EndpointSecurity
import OSLog


// MARK: - Compiled indicators
/// A set of indicators compiled for the Security Extension, which a capture lane evaluates each event it builds
/// against (``hits(for:values:)``). It's immutable, so every lane shares one, and a new set replaces it whole: an
/// event is judged entirely by one set or the other.
///
/// - Each indicator that's on and compiles runs on the event types it names (``IndicatorCompiler``), in the set's
///   order, so its hits come out in that order. The rules for a type are in an array by the type's number, which is
///   bounds-checked: a type this build doesn't know, or a newer one, has none.
/// - An event is evaluated only against the rules of its type it could match: those that need nothing the set's
///   ``IndicatorIndex`` checks, and those whose literals its values have, found for all of them at once.
/// - Indicators with the same predicate, byte for byte (``Source``), share one compiled program, and a set made from
///   another (`reusing:`) compiles only the predicates that one didn't have, and copies the rest from its store.
/// - Each rule's ``IndicatorHit`` is made once, here, so a hit costs a copy of it.
/// - One that doesn't compile is kept in ``problems``, by identity, which may repeat.
/// - Its programs are frozen in buffers of its own (``FrozenPrograms``), so lanes sharing it touch no reference count
///   of its as they evaluate: it's `@unchecked Sendable` for those buffers, which nothing changes after `init`.
/// - A record lists at most ``hitLimit`` hits. An event that matches more counts in its lane's
///   ``MessageValueCache/cappedEvents``, and the lane's first is logged as a fault.
/// - Each event is evaluated within its ``ScanBudget``. A rule the budget or Foundation's 64 KiB window left
///   undecided is undetermined (``evaluate(_:values:)``), at most ``undeterminedLimit`` of them listed, and never a
///   hit. While both lists are under their limits, a rule neither hit nor undetermined doesn't match. A list at its
///   limit may have been cut short: a hit past ``hitLimit`` ends the scan, so later rules aren't evaluated, and
///   undetermined ones past the limit are only counted. An event whose budget ran out counts in
///   ``MessageValueCache/scanExhaustedEvents``, and the lane's first is logged as a fault.
public final class CompiledIndicators: @unchecked Sendable {
    /// The most hits a record lists.
    public static let hitLimit = 32
    /// The most undetermined indicators an evaluation lists, apart from its hits.
    public static let undeterminedLimit = 32
    /// The indicators Mac Monitor ships, by identity.
    public static let shippedDefaults = Indicator.byID(Indicator.defaults)
    /// Logs the first event of a lane that matched more than ``hitLimit`` indicators.
    static let logger = Logger(subsystem: "com.swiftlydetecting.agent.securityextension",
                               category: "CompiledIndicators")

    /// An indicator the Security Extension can't run, and why.
    public struct Problem: Equatable, Sendable {
        /// The indicator's identity.
        public let id: UUID
        /// Why it can't run.
        public let problem: SensorProblem

        /// The reason, as Settings shows it.
        public var reason: String { problem.description }
    }

    /// Its programs and its index by type, as lanes evaluate them.
    private let frozen: FrozenPrograms
    /// Its rules for each type by the literals they need, which pick the rules an event is evaluated against.
    private let index: IndicatorIndex
    /// The record fields its rules read (``RecordPathTrie``), which each event's values read in one walk when a rule
    /// first asks for one.
    private let recordPaths: RecordPathTrie?
    /// Does a rule read an exec's launched-by parent, which Launch Services can change after the exec is stamped
    /// (``LaunchServicesHold``)?
    let readsLaunchedByParent: Bool
    /// Each rule's hit, in the set's order.
    let ruleHits: ContiguousArray<IndicatorHit>
    /// Every predicate compiled, by its text's bytes: the types it runs on and its program, or its problem. A set made
    /// from this one copies its programs from ``frozen``.
    private let compiled: [Source: Compiled]

    /// The indicators it can't run, in the set's order.
    public let problems: [Problem]
    /// How many predicates it compiled rather than reused.
    let compiledCount: Int

    /// How many distinct programs it holds: one for each predicate that compiles, those of indicators that are off
    /// too.
    let programCount: Int

    /// How many rules it runs: the indicators that are on and compile.
    public var count: Int { ruleHits.count }

    /// How many rules an event of a type is evaluated against.
    ///
    /// - Parameter type: The type's number.
    /// - Returns: Its rules' count, 0 for a type this build doesn't know.
    func candidates(forType type: Int) -> Int {
        (0..<frozen.typeCount).contains(type) ? frozen.slots(forType: type).count : 0
    }

    /// How many nodes its distinct programs have in all, those of indicators that are off too: what
    /// ``IndicatorLimits/maxNodes`` caps.
    public var nodeCount: Int { frozen.nodeCount }

    /// The event type it runs the most rules on, and how many: what ``IndicatorLimits/maxRulesPerType`` caps.
    ///
    /// - Returns: The type's number and its rules' count, or `nil` when it runs none.
    public func busiestType() -> (type: Int, rules: Int)? {
        (0..<frozen.typeCount).map { (type: $0, rules: frozen.slots(forType: $0).count) }
            .filter { $0.rules > 0 }.max { $0.rules < $1.rules }
    }

    /// Compile a set of indicators.
    ///
    /// - Parameters:
    ///   - indicators: The indicators, in order. Those that are off aren't run, but their problems are listed.
    ///   - defaults: Those Mac Monitor ships, by identity. Each hit says whether its indicator is one, and whether
    ///     this Mac edited it, worked out here once rather than for each event.
    ///   - previous: A set whose compiled predicates to reuse, by their text's bytes.
    public init(_ indicators: [Indicator], defaults: [UUID: Indicator] = shippedDefaults,
                reusing previous: CompiledIndicators? = nil) {
        var compiled: [Source: Compiled] = [:]
        compiled.reserveCapacity(indicators.count)
        var origins: [FrozenPrograms.Origin] = []
        var rules: [Int32] = [], ruleHits = ContiguousArray<IndicatorHit>()
        var byType = [[Int32]](repeating: [], count: Int(ES_EVENT_TYPE_LAST.rawValue))
        var problems: [Problem] = []
        var compiledCount = 0
        for indicator in indicators {
            let source = Source(indicator.predicate)
            let entry: Compiled
            if let known = compiled[source] {
                entry = known
            } else {
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
            }
            switch entry {
            case .problem(let problem):
                problems.append(Problem(id: indicator.id, problem: problem))
            case .rule(let types, let program) where indicator.isEnabled:
                let index = Int32(rules.count)
                rules.append(program)
                ruleHits.append(IndicatorHit(indicator, against: defaults, evaluatedBy: .securityExtension))
                for type in types where byType.indices.contains(type) { byType[type].append(index) }
            case .rule:
                continue
            }
        }
        frozen = FrozenPrograms(origins: origins, rules: rules, byType: byType)
        index = IndicatorIndex(frozen)
        let nodes = frozen.view.nodes
        let compares = nodes.lazy.filter { $0.kind == .compare || $0.kind == .anyCompare }
        let recordPaths = RecordPathTrie(compares.map(\.field))
        self.recordPaths = recordPaths.isEmpty ? nil : recordPaths
        readsLaunchedByParent = recordPaths.fields.contains { $0.path.hasPrefix(Self.launchedByParent) }
        programCount = origins.count
        self.ruleHits = ruleHits
        self.compiled = compiled
        self.problems = problems
        self.compiledCount = compiledCount
    }

    /// The indicators an event matches, in the set's order, at most ``hitLimit``: what its record lists.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - values: The lane's values.
    /// - Returns: Its hits (``evaluate(_:values:)``). Empty, which allocates nothing, when it matches none.
    public func hits(for message: borrowing Message, values: inout MessageValueCache) -> [IndicatorHit] {
        evaluate(message, values: &values).hits
    }

    /// What the Security Extension decides for an event: the indicators it matches, and those its ``ScanBudget`` or
    /// Foundation's window left undecided, each in the set's order. Each call is a new event: the lane's values,
    /// its budget's included, are reset before and after it.
    ///
    /// Rules are evaluated in the set's order until a hit past ``hitLimit``, which stops it as before. Undetermined
    /// rules are listed up to ``undeterminedLimit`` and counted past it, apart from the hits, so they can't bury one.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - values: The lane's values.
    /// - Returns: The hits and the undetermined. Both empty, which allocates nothing, when it matches none.
    public func evaluate(_ message: borrowing Message, values: inout MessageValueCache) -> IndicatorEvaluation {
        values.reset()
        defer { values.reset() }
        values.recordPaths = recordPaths
        let type = Self.eventType(of: message)
        guard (0..<frozen.typeCount).contains(type) else { return IndicatorEvaluation() }
        let slots = frozen.slots(forType: type)
        guard !slots.isEmpty else { return IndicatorEvaluation() }
        var words = values.takeCandidates(index.words(forType: type))
        defer { values.returnCandidates(words) }
        index.candidates(forType: type, message, values: &values, into: &words)
        let view = frozen.view
        var result = IndicatorEvaluation()
        scan: for word in 0..<index.words(forType: type) {
            var bits = words[word]
            while bits != 0 {
                let slot = slots.lowerBound + word << 6 + bits.trailingZeroBitCount
                bits &= bits &- 1
                let rule = frozen.rule(at: slot)
                values.beginRule()
                switch view.verdict(root: frozen.root(of: rule), message, eventType: type, values: &values) {
                case .no:
                    continue
                case .yes:
                    guard result.hits.count < Self.hitLimit else {
                        noteCapped(message, values: &values)
                        break scan
                    }
                    result.hits.append(ruleHits[rule])
                case .unknown:
                    result.undeterminedCount += 1
                    guard result.undetermined.count < Self.undeterminedLimit else { continue }
                    let reason: UndeterminedReason = values.scan.refusedThisRule ? .scanBudget : .valueLimit
                    result.undetermined.append(IndicatorUndetermined(ruleHits[rule], reason: reason))
                }
            }
        }
        if values.scan.refusedThisEvent { noteExhausted(message, values: &values) }
        if result.undeterminedCount > 0 { values.undeterminedEvents += 1 }
        return result
    }

    /// The rules of an event's type its set's index picks for it, by their position among the type's rules: every
    /// one it could match, which ``hits(for:values:)`` evaluates. Tests check them, and the benchmarks count them.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - values: The lane's values.
    ///   - budget: The event's allowance (``ScanBudget/limit``) the index works within: none by default.
    /// - Returns: The positions, in order.
    func candidates(for message: borrowing Message, values: inout MessageValueCache, budget: Int = .max) -> [Int] {
        values.reset()
        values.recordPaths = recordPaths
        let limit = values.scan.limit
        values.scan.limit = budget
        defer {
            values.reset()
            values.scan.limit = limit
        }
        let type = Self.eventType(of: message)
        let count = candidates(forType: type)
        guard count > 0 else { return [] }
        var words = values.takeCandidates(index.words(forType: type))
        defer { values.returnCandidates(words) }
        index.candidates(forType: type, message, values: &values, into: &words)
        return (0..<count).filter { words[$0 >> 6] & 1 << UInt64($0 & 63) != 0 }
    }

    /// The rules of an event's type it matches, each evaluated whichever the index picks, by their position among the
    /// type's rules: what tests check the index's candidates against.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - values: The lane's values.
    /// - Returns: The positions.
    func matchingPositions(for message: borrowing Message, values: inout MessageValueCache) -> Set<Int> {
        values.reset()
        values.recordPaths = recordPaths
        let limit = values.scan.limit
        values.scan.limit = .max
        defer {
            values.reset()
            values.scan.limit = limit
        }
        let type = Self.eventType(of: message)
        guard candidates(forType: type) > 0 else { return [] }
        let slots = frozen.slots(forType: type), view = frozen.view
        var matching = Set<Int>()
        for slot in slots
        where view.matches(root: frozen.root(of: frozen.rule(at: slot)), message, eventType: type, values: &values) {
            matching.insert(slot - slots.lowerBound)
        }
        return matching
    }

    /// Count an event that matched more than ``hitLimit`` indicators, and log the lane's first as a fault.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - values: The lane's values, which count it.
    private func noteCapped(_ message: borrowing Message, values: inout MessageValueCache) {
        values.cappedEvents += 1
        guard values.cappedEvents == 1 else { return }
        let name = message.es_event_type
        Self.logger.fault("""
            An event matched more than \(Self.hitLimit) indicators: its record lists the first \
            \(Self.hitLimit). Event type: \(name, privacy: .public)
            """)
    }

    /// Count an event whose scan budget ran out somewhere, and log the lane's first as a fault: its type, the pools
    /// refused and the units spent, never its content.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - values: The lane's values, which count it.
    private func noteExhausted(_ message: borrowing Message, values: inout MessageValueCache) {
        values.scanExhaustedEvents += 1
        guard values.scanExhaustedEvents == 1 else { return }
        let name = message.es_event_type, pools = ScanPool.names(values.scan.refusedPools)
        let spent = values.scan.spent
        Self.logger.fault("""
            An event's indicator scan budget ran out: some indicators were left undetermined. Event type: \
            \(name, privacy: .public), pools refused: \(pools, privacy: .public), units spent: \
            \(spent, privacy: .public) of \(ScanBudget.eventLimit, privacy: .public)
            """)
    }

    /// Stamp an event with what the Security Extension decided for it (``evaluate(_:values:)``), as its record lists
    /// it: the hits, each said to be the Security Extension's, empty when it matches none, and the indicators it
    /// couldn't rule out, `nil` when it decided every one. The no-match path allocates nothing.
    ///
    /// - Parameters:
    ///   - message: The event, whose ``Message/indicators`` and ``Message/indicators_undetermined`` it sets.
    ///   - values: The lane's values.
    public func stamp(_ message: inout Message, values: inout MessageValueCache) {
        let result = evaluate(message, values: &values), undetermined = result.undetermined
        message.indicators = IndicatorVerdicts(result.hits)
        message.indicators_undetermined = undetermined.isEmpty ? nil : UndeterminedIndicators(undetermined)
    }

    /// The key path of an exec's launched-by parent, as a rule names the fields under it.
    static let launchedByParent = "event.exec.launched_by_parent."

    /// Free the frozen programs and the index, which no lane reads once the set is gone.
    deinit {
        frozen.deallocate()
        index.deallocate()
    }

    /// What a record says the Security Extension found: `nil` when it didn't evaluate the event, as without a set,
    /// and the hits otherwise, empty when none matched.
    ///
    /// - Parameters:
    ///   - indicators: The lane's set, if it has one.
    ///   - message: The event.
    ///   - values: The lane's values.
    /// - Returns: The verdicts.
    public static func verdicts(of indicators: CompiledIndicators?, for message: borrowing Message,
                                values: inout MessageValueCache) -> [IndicatorHit]? {
        indicators?.hits(for: message, values: &values)
    }

    /// An event's type, by number, as the rules are kept: -1 for one Mac Monitor doesn't model, whose record calls it
    /// "NOT MAPPED".
    ///
    /// - Parameter message: The event.
    /// - Returns: Its type's number.
    static func eventType(of message: borrowing Message) -> Int {
        if case .unknown = message.event { return -1 }
        return message.event_type
    }
}


// MARK: - Evaluations
/// What the Security Extension decided for one event (``CompiledIndicators/evaluate(_:values:)``).
public struct IndicatorEvaluation: Equatable, Sendable {
    /// The indicators it matched, in the set's order, at most ``CompiledIndicators/hitLimit``.
    public var hits: [IndicatorHit] = []
    /// The indicators it couldn't rule out, in the set's order, at most ``CompiledIndicators/undeterminedLimit``.
    public var undetermined: [IndicatorUndetermined] = []
    /// How many it couldn't rule out, those past the limit too.
    public var undeterminedCount = 0
}
