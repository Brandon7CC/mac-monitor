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
/// - A sequence's steps are rules too, which tag nothing alone: the event that completes one of its chains gets its
///   hit (``advanceSequences(_:values:chains:into:)``). Its chains are in a ``SequenceTable`` each capture session has
///   of its own (``SessionChains``), which every lane of the session shares. The set's own (``chains``), which a set
///   made from this one keeps while the sequence is the same, are for code evaluating it alone.
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
    /// Logs a lane's first event that matched more than ``hitLimit`` indicators, and a lane's first event whose scan
    /// budget ran out.
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

    /// Its programs and its index by type, as lanes evaluate them. A set made from this one copies its programs.
    let frozen: FrozenPrograms
    /// Its rules for each type by the literals they need, which pick the rules an event is evaluated against.
    private let index: IndicatorIndex
    /// The record fields its rules read (``RecordPathTrie``), which each event's values read in one walk when a rule
    /// first asks for one.
    let recordPaths: RecordPathTrie?
    /// Does a rule, a sequence's step or its keys read an exec's launched-by parent, which Launch Services can change
    /// after the exec is stamped (``LaunchServicesHold``)?
    let readsLaunchedByParent: Bool
    /// Each rule's hit, in the set's order: a step's is its sequence's.
    let ruleHits: ContiguousArray<IndicatorHit>
    /// Each rule's sequence and step (``stepRule(sequence:step:)``), or -1 for a rule on one event of its own.
    let ruleSteps: ContiguousArray<Int32>
    /// Each step's program, by its step (``stepRule(sequence:step:)``), to say what a completed chain's last event
    /// matched.
    let stepRoots: [Int32: Int]
    /// The sequences it runs, in the set's order.
    let sequences: [CompiledSequence]
    /// Each indicator's place in the set, by identity: its first rule's. A sequence's hit is put among an event's
    /// others by it.
    let positions: [UUID: Int32]
    /// The most chains each of its sequences holds as it advances them: an even share of
    /// ``SequenceTable/totalChains``.
    let chainShare: Int
    /// Its own chains for its sequences, which an evaluation given no session's advances, as
    /// `macmonitor indicators test` does.
    let chains: SessionChains
    /// Every predicate compiled, by its text's bytes: the types it runs on and its program, or its problem. A set made
    /// from this one copies its programs from ``frozen``.
    let compiled: [Source: Compiled]

    /// The indicators it can't run, in the set's order.
    public let problems: [Problem]
    /// How many predicates it compiled rather than reused.
    let compiledCount: Int

    /// How many distinct programs it holds: one for each predicate that compiles, those of indicators that are off
    /// too.
    let programCount: Int

    /// How many indicators it runs: those that are on and compile, a sequence once however many steps it has.
    public var count: Int { ruleHits.count - ruleSteps.count(where: { $0 >= 0 }) + sequences.count }

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
    ///   - pack: The indicator pack those are, which each of their hits names, or 0 for a build's own.
    ///   - previous: A set whose compiled predicates to reuse, by their text's bytes.
    public init(_ indicators: [Indicator], defaults: [UUID: Indicator] = shippedDefaults, pack: Int = 0,
                reusing previous: CompiledIndicators? = nil) {
        var builder = Builder(defaults: defaults, pack: pack, previous: previous, capacity: indicators.count)
        for indicator in indicators { builder.add(indicator) }
        frozen = FrozenPrograms(origins: builder.origins, rules: builder.rules, byType: builder.byType)
        index = IndicatorIndex(frozen)
        let fields = frozen.view.nodes.flatMap(\.fields) + builder.sequences.flatMap(\.table.program.fields)
        let recordPaths = RecordPathTrie(fields)
        self.recordPaths = recordPaths.isEmpty ? nil : recordPaths
        readsLaunchedByParent = recordPaths.fields.contains { $0.path.hasPrefix(Self.launchedByParent) }
            || fields.contains { $0.lineageOffset.map(LineageField.chain(at:)) == .launchedBy }
        programCount = builder.origins.count
        ruleHits = builder.ruleHits
        ruleSteps = builder.ruleSteps
        var stepRoots: [Int32: Int] = [:]
        for (rule, step) in builder.ruleSteps.enumerated() where step >= 0 { stepRoots[step] = frozen.root(of: rule) }
        self.stepRoots = stepRoots
        sequences = builder.sequences
        positions = Dictionary(builder.ruleHits.enumerated().map { ($1.id, Int32($0)) }) { first, _ in first }
        compiled = builder.compiled
        problems = builder.problems
        compiledCount = builder.compiledCount
        chainShare = SessionChains.share(of: SequenceTable.totalChains, among: sequences.count)
        chains = SessionChains(tables: sequences.map(\.table), sequences: sequences, share: chainShare)
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
    /// its budget's included, are reset before and after it, and its steps advance the set's sequences, unless they're
    /// deferred to the event's turn.
    ///
    /// Rules are evaluated in the set's order until a hit past ``hitLimit``, which stops it as before. Undetermined
    /// rules are listed up to ``undeterminedLimit`` and counted past it, apart from the hits, so they can't bury one.
    ///
    /// - Parameters:
    ///   - message: The event.
    ///   - values: The lane's values.
    ///   - chains: The capture session's chains, or `nil` for the set's own.
    ///   - deferringSteps: Leave the sequences as they are, and hand back the steps it matched
    ///     (``IndicatorEvaluation/steps``) to advance them once it's the event's turn
    ///     (``advance(_:steps:values:chains:)``), as the exec lane does (``LaunchServicesHold``).
    /// - Returns: The hits and the undetermined. Both empty, which allocates nothing, when it matches none.
    public func evaluate(_ message: borrowing Message, values: inout MessageValueCache, chains: SessionChains? = nil,
                         deferringSteps: Bool = false) -> IndicatorEvaluation {
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
        /// The last sequence a step of which was undetermined, so the event lists it once.
        var uncertainSequence: Int32 = -1
        /// Did a hit past ``hitLimit`` end the scan, which counted the event?
        var capped = false
        /// Each hit's program, to say what it matched once the scan is over.
        var roots = ContiguousArray<Int>()
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
                    /// A rule's step is read only once it matched, so a rule that doesn't match costs what it did
                    /// before sequences.
                    let step = ruleSteps[rule]
                    guard step < 0 else {
                        values.noteStep(step)
                        continue
                    }
                    guard result.hits.count < Self.hitLimit else {
                        noteCapped(message, values: &values)
                        capped = true
                        break scan
                    }
                    result.hits.append(ruleHits[rule])
                    roots.append(frozen.root(of: rule))
                case .unknown:
                    let step = ruleSteps[rule]
                    if step >= 0 {
                        guard step >> 3 != uncertainSequence else { continue }
                        uncertainSequence = step >> 3
                    }
                    result.undeterminedCount += 1
                    guard result.undetermined.count < Self.undeterminedLimit else { continue }
                    let reason: UndeterminedReason = values.scan.refusedThisRule ? .scanBudget : .valueLimit
                    result.undetermined.append(IndicatorUndetermined(ruleHits[rule], reason: reason))
                }
            }
        }
        for index in result.hits.indices {
            result.hits[index].matched = matched(roots: CollectionOfOne(roots[index]), message, type: type,
                                                 values: &values)
        }
        if values.hasStepMatches {
            if deferringSteps {
                result.steps = values.takeStepMatches()
            } else {
                advanceSequences(message, values: &values, chains: chains ?? self.chains, capped: capped,
                                 into: &result)
            }
        }
        if values.scan.refusedThisEvent { noteExhausted(message, values: &values) }
        if result.undeterminedCount > 0 { values.undeterminedEvents += 1 }
        return result
    }

    /// What made programs an event matched match: the comparisons it passed, each with the value it had
    /// (``IndicatorProgram/View/matched(root:_:eventType:values:into:)``).
    ///
    /// It's worked out after the event's rules are all decided, within an allowance of its own that an event's
    /// hits share, so explaining a hit never leaves a later rule short, and at most doubles what an event can cost.
    /// The scan's own account and Foundation's counts are put back as they were, for the lane's counts.
    ///
    /// - Parameters:
    ///   - roots: The programs' root nodes: a rule's one, or those of the steps of a sequence the event matched.
    ///   - message: The event.
    ///   - type: Its type's number.
    ///   - values: The lane's values for this event.
    /// - Returns: What they matched, or `nil` when they compare nothing but the event's type.
    func matched(roots: some Sequence<Int>, _ message: borrowing Message, type: Int,
                 values: inout MessageValueCache) -> [IndicatorMatchedField]? {
        let scan = values.scan
        let (truncations, stringsMade) = (values.foundation.truncations, values.foundation.stringsMade)
        var allowance = values.explaining ?? ScanBudget()
        if values.explaining == nil { allowance.limit = scan.limit }
        values.scan = allowance
        defer {
            values.explaining = values.scan
            values.scan = scan
            values.foundation.restoreCounts(truncations: truncations, stringsMade: stringsMade)
        }
        values.beginRule()
        var fields: [IndicatorMatchedField] = []
        let view = frozen.view
        for root in roots { view.matched(root: root, message, eventType: type, values: &values, into: &fields) }
        return fields.isEmpty ? nil : fields
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
    func noteCapped(_ message: borrowing Message, values: inout MessageValueCache) {
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
    ///   - chains: The capture session's chains, or `nil` for the set's own.
    ///   - deferringSteps: Leave the sequences, to advance them once it's the event's turn
    ///     (``evaluate(_:values:chains:deferringSteps:)``).
    /// - Returns: The sequence steps it matched and left, for ``advance(_:steps:values:chains:)``: none unless
    ///   deferring.
    @discardableResult
    public func stamp(_ message: inout Message, values: inout MessageValueCache, chains: SessionChains? = nil,
                      deferringSteps: Bool = false) -> ContiguousArray<Int32> {
        let result = evaluate(message, values: &values, chains: chains, deferringSteps: deferringSteps)
        let undetermined = result.undetermined
        message.indicators = IndicatorVerdicts(result.hits)
        message.indicators_undetermined = undetermined.isEmpty ? nil : UndeterminedIndicators(undetermined)
        return result.steps
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
    /// The sequence steps it matched, in the set's order, when they were deferred to the event's turn
    /// (``CompiledIndicators/advance(_:steps:values:chains:)``): none otherwise.
    var steps = ContiguousArray<Int32>()
}
