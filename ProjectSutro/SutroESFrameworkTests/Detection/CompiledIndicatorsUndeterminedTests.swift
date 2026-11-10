//
//  CompiledIndicatorsUndeterminedTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/8/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Undetermined indicators
/// Pins what ``CompiledIndicators/evaluate(_:values:)`` couldn't decide: the rules a hostile exec's budget leaves
/// undetermined, in the set's order, rules on other fields still decided by their own pools, the 32-entry list kept
/// apart from the hit cap, and the lane's counts. A rule left out of both lists never matches.
final class CompiledIndicatorsUndeterminedTests: XCTestCase {
    /// The shipped rules that read the crafted command line far enough to run out of its pool.
    static let commandLineRules = ["Scheduled job added", "Launch job loaded", "Dylib inserted",
                                   "Terminal startup command", "Login hook set"]

    /// The crafted launchctl copy lists exactly the five rules that read its command line, in the set's order, for
    /// its budget. The rest are decided, and nothing it matches with no budget is missing from both lists.
    func testTheCraftedLaunchctlCopyListsItsCommandLineRules() throws {
        let message = try AdversarialEvent.asciiCrafted.message(self)
        let (budgeted, unlimited) = evaluations(of: message)
        XCTAssertEqual(budgeted.undetermined.map(\.hit.name), Self.commandLineRules)
        XCTAssertEqual(Set(budgeted.undetermined.map(\.reason)), [.scanBudget])
        assertNoSilentMiss(budgeted, unlimited)
        XCTAssertTrue(budgeted.hits.allSatisfy { !Self.commandLineRules.contains($0.name) })
    }

    /// A rule first in the set that spends the crafted command line's pool (``drain``), more than the whole event's
    /// allowance would pay for, leaves a metered search of the target's path after it decided: the path spends from
    /// the other fields' pool, which the command line can't. With one allowance for the event, it would be refused.
    func testOtherFieldsStillDecideBesideAPaddedCommandLine() throws {
        let message = try changed(AdversarialEvent.asciiCrafted.message(self)) {
            $0.target.executable?.path = "/tmp/Build/Products/a"
        }
        let unlimited = try verdict(execProgram(Self.drainComparison), on: message, limit: .max)
        XCTAssertEqual(unlimited.0, .yes)
        XCTAssertGreaterThan(unlimited.1.scan.spent, ScanBudget.eventLimit)
        let built = execIndicator("Built", #"event.exec.target.executable.path CONTAINS "/Build/Products/""#)
        var values = MessageValueCache()
        let evaluation = CompiledIndicators([drain, built]).evaluate(message, values: &values)
        XCTAssertEqual(evaluation.undetermined.map(\.hit.name), ["Drain"])
        XCTAssertEqual(evaluation.hits.map(\.name), ["Built"])
        let index: UInt8 = 1 << UInt8(ScanPool.index.rawValue)
        XCTAssertEqual(values.lastEventRefused & ~index, 1 << UInt8(ScanPool.commandLine.rawValue),
                       "only the command line's pool, and the index's")
    }

    /// Dylib inserted, by its environment, on an exec whose command line is padded to 1 MiB and spent by ``drain``
    /// first, is a hit: its Xcode exclusion's search of the target's path spends from the other fields' pool.
    func testAPaddedCommandLineCantBlindDylibInsertedsExclusion() throws {
        let message = try changed(AdversarialEvent.asciiCrafted.message(self)) {
            $0.target.executable?.path = "/tmp/a"
            $0.env = ["HOME=/Users/a", "DYLD_INSERT_LIBRARIES=/tmp/x.dylib"]
        }
        var values = MessageValueCache()
        let evaluation = CompiledIndicators([drain] + Indicator.defaults).evaluate(message, values: &values)
        XCTAssertEqual(evaluation.undetermined.first?.hit.name, "Drain")
        XCTAssertTrue(evaluation.hits.map(\.id).contains(try shippedID("Dylib inserted")))
        XCTAssertFalse(evaluation.undetermined.map(\.hit.name).contains("Dylib inserted"))
    }

    /// Forty rules left undetermined list the first 32 and count 40, the event counted once in each of the lane's
    /// counts. The index, with no budget, kept every one of them.
    func testUndeterminedRulesAreListedUpTo32() throws {
        let rules = (0..<40).map { execIndicator("Q\($0)", #"event.exec.command_line CONTAINS "q\#($0)""#) }
        let evaluation = try evaluateWithNoBudget(CompiledIndicators(rules))
        XCTAssertEqual(evaluation.result.undetermined.map(\.hit.id), rules.prefix(32).map(\.id))
        XCTAssertEqual(evaluation.result.undeterminedCount, 40)
        XCTAssertEqual(evaluation.result.hits, [])
        XCTAssertEqual(evaluation.values.scanExhaustedEvents, 1)
        XCTAssertEqual(evaluation.values.undeterminedEvents, 1)
    }

    /// The hit cap and the undetermined list are apart: five undetermined rules before 40 that every exec matches
    /// list five undetermined and the first 32 hits, and the event counts as capped too.
    func testTheHitCapAndTheUndeterminedListAreApart() throws {
        let unknown = (0..<5).map { execIndicator("Q\($0)", #"event.exec.command_line CONTAINS "q\#($0)""#) }
        let every = (0..<40).map { _ in ownIndicator("Every", Self.execCheck) }
        let evaluation = try evaluateWithNoBudget(CompiledIndicators(unknown + every))
        XCTAssertEqual(evaluation.result.undetermined.map(\.hit.id), unknown.map(\.id))
        XCTAssertEqual(evaluation.result.hits.map(\.id), every.prefix(32).map(\.id))
        XCTAssertEqual(evaluation.values.cappedEvents, 1)
        XCTAssertEqual(evaluation.values.undeterminedEvents, 1)
    }

    /// An ordinary exec, and every event of the synthetic corpus, leave nothing undetermined and refuse nothing.
    func testOrdinaryEventsAreAllDecided() throws {
        var values = MessageValueCache()
        for message in try SyntheticCorpus.records().map(\.message) + [benchmarkExec()] {
            XCTAssertEqual(Self.shippedIndicators.evaluate(message, values: &values).undetermined, [])
            XCTAssertEqual(values.lastEventRefused, 0, message.es_event_type)
            XCTAssertLessThan(values.lastEventUnits, 2_000, message.es_event_type)
        }
        XCTAssertEqual(values.scanExhaustedEvents, 0)
        XCTAssertEqual(values.undeterminedEvents, 0)
    }

    /// A 1 MiB ASCII command line and script, and a benign 16 KiB non-ASCII command line, from a target outside an
    /// app bundle, leave every shipped rule decided and refuse nothing, the index's pool included: a rule that also
    /// needs a target's path, as Browser extension sideloaded does, is anchored and ruled out on the path, never on a
    /// search of the command line, so the line's pools still pay for the rules that need it. From a target inside an
    /// app bundle that rule does search the line, and can still spend the pool the later rules share.
    func testAHostileCommandLineLeavesTheShippedRulesDecided() throws {
        var values = MessageValueCache()
        for event in [AdversarialEvent.ascii, .nonascii16k] {
            let evaluation = Self.shippedIndicators.evaluate(try event.message(self), values: &values)
            XCTAssertEqual(evaluation.undetermined, [], event.rawValue)
            XCTAssertEqual(values.lastEventRefused, 0, "\(event.rawValue): \(ScanPool.names(values.lastEventRefused))")
        }
    }

    /// A stamp writes what the evaluation decided: the crafted launchctl copy's hits as its verdicts and its five
    /// command-line rules, with their reason, as ``Message/indicators_undetermined``. An ordinary exec, decided whole,
    /// has none: `nil`, never an empty list.
    func testAStampListsTheUndetermined() throws {
        var crafted = try AdversarialEvent.asciiCrafted.message(self)
        let evaluation = evaluations(of: crafted).budgeted
        var values = MessageValueCache()
        Self.shippedIndicators.stamp(&crafted, values: &values)
        XCTAssertEqual(crafted.indicators, IndicatorVerdicts(evaluation.hits))
        XCTAssertEqual(crafted.indicators_undetermined, UndeterminedIndicators(evaluation.undetermined))
        XCTAssertEqual(crafted.indicators_undetermined?.entries.map(\.hit.name), Self.commandLineRules)
        var ordinary = try benchmarkExec()
        Self.shippedIndicators.stamp(&ordinary, values: &values)
        XCTAssertNotNil(ordinary.indicators)
        XCTAssertNil(ordinary.indicators_undetermined)
    }
}


// MARK: - Helpers
extension CompiledIndicatorsUndeterminedTests {
    /// A search of the crafted command line for its repeated part and the space its tail starts with, which matches
    /// most of every repetition before it fails, and is found only at the line's end.
    static let drainComparison = #"event.exec.command_line CONTAINS ""# + AdversarialEvent.craftedUnit + #" com""#

    /// A rule of someone's own that spends the crafted command line's whole pool (``drainComparison``).
    var drain: Indicator { execIndicator("Drain", Self.drainComparison) }

    /// The shipped indicators on an event, with the event's budget and with none.
    ///
    /// - Parameter message: The event.
    /// - Returns: Both evaluations.
    func evaluations(of message: Message) -> (budgeted: IndicatorEvaluation, unlimited: IndicatorEvaluation) {
        var values = MessageValueCache()
        let budgeted = Self.shippedIndicators.evaluate(message, values: &values)
        values.scan.limit = .max
        return (budgeted, Self.shippedIndicators.evaluate(message, values: &values))
    }

    /// Check that a budget only turned hits into undetermined ones: its hits are the unlimited ones', and every
    /// unlimited hit is a hit or undetermined.
    ///
    /// - Parameters:
    ///   - budgeted: The evaluation with a budget.
    ///   - unlimited: The evaluation with none, whose undetermined are the window's only.
    func assertNoSilentMiss(_ budgeted: IndicatorEvaluation, _ unlimited: IndicatorEvaluation,
                            file: StaticString = #filePath, line: UInt = #line) {
        let hits = Set(budgeted.hits.map(\.id)), listed = hits.union(budgeted.undetermined.map(\.hit.id))
        XCTAssertTrue(hits.isSubset(of: unlimited.hits.map(\.id)), file: file, line: line)
        XCTAssertTrue(Set(unlimited.hits.map(\.id)).isSubset(of: listed), file: file, line: line)
    }

    /// An exec, its command line one a search has to read, changed.
    ///
    /// - Parameters:
    ///   - message: The exec.
    ///   - change: Changes it.
    /// - Returns: It, changed.
    /// - Throws: A failure when it isn't an exec.
    func changed(_ message: Message, _ change: (inout ProcessExecEvent) -> Void) throws -> Message {
        var message = message
        var exec = try XCTUnwrap(message.event.exec)
        change(&exec)
        message.event = .exec(exec)
        return message
    }

    /// Evaluate a set on an exec with no budget at all.
    ///
    /// - Parameter compiled: The set.
    /// - Returns: The evaluation, and the cache after it.
    /// - Throws: The error making the exec.
    func evaluateWithNoBudget(_ compiled: CompiledIndicators) throws
        -> (result: IndicatorEvaluation, values: MessageValueCache) {
        let message = try corpusExec { $0.command_line = String(repeating: "x y ", count: 64) }
        var values = MessageValueCache()
        values.scan.limit = 0
        return (compiled.evaluate(message, values: &values), values)
    }
}
