//
//  FieldFilterConflictsTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/17/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Rules a field filter starves
/// Pins which rules Settings and `macmonitor stream` warn about while only modified closes are recorded: a rule
/// that runs on closes alone and can only match an unmodified one, and a sequence's step like it. A rule that
/// just sees fewer closes isn't warned about.
final class FieldFilterConflictsTests: XCTestCase {
    private let filter = FieldFilter.modifiedCloses

    /// A rule that can only match an unmodified close is starved, however it says so. One that takes modified
    /// closes, any close, or another event type as well still has events to match.
    func testOnlyARuleThatNeedsUnmodifiedClosesIsStarved() {
        let starved = [
            "event.close != nil AND event.close.modified == NO",
            "event.close != nil AND event.close.modified == 0 AND target_path ENDSWITH \".txt\"",
            "event.close != nil AND event.close.modified != YES",
            "event.close != nil AND NOT (event.close.modified == YES)",
            "es_event_type == \"ES_EVENT_TYPE_NOTIFY_CLOSE\" AND event.close.modified IN {NO}",
            "event.close != nil AND (event.close.modified == NO OR (event.close.modified == NO AND target_path != nil))",
            "event.close != nil AND event.close.modified == 0.0",
        ]
        for predicate in starved { XCTAssertTrue(filter.starves(predicate), predicate) }
        let fed = [
            "event.close != nil AND event.close.modified == YES",
            "event.close != nil AND target_path ENDSWITH \".txt\"",
            "event.close != nil AND (event.close.modified == NO OR target_path ENDSWITH \".txt\")",
            "(event.close != nil AND event.close.modified == NO) OR event.rename != nil",
            "event.exec != nil AND event.exec.target.executable.path ENDSWITH \"/curl\"",
            "event.close != nil AND event.close.modified == NO AND event.close.modified == YES",
            "event.close != nil AND (event.close.modified == 1.0 OR event.close.modified == NO)",
            "not a predicate (",
        ]
        for predicate in fed { XCTAssertFalse(filter.starves(predicate), predicate) }
    }

    /// The indicators that are on are checked, a sequence step by step, and each conflict says what it means for
    /// its indicator. No filter, no conflict.
    func testConflictsNameTheIndicatorAndTheStep() {
        let unmodified = "event.close != nil AND event.close.modified == NO"
        let rule = ownIndicator("Read and closed", unmodified)
        var off = ownIndicator("Off", unmodified)
        off.isEnabled = false
        let fine = ownIndicator("Written", "event.close != nil AND event.close.modified == YES")
        let steps = [IndicatorSequence.Step(name: "opened", predicate: "event.open != nil"),
                     IndicatorSequence.Step(name: "closed", predicate: unmodified)]
        let sequence = sequenceIndicator(IndicatorSequence(order: .ordered, within: 5, steps: steps))
        let conflicts = FieldFilter.conflicts(of: [filter], with: [rule, off, fine, sequence])
        XCTAssertEqual(conflicts, [
            FieldFilterConflict(indicator: rule.id, name: "Read and closed", step: nil, filter: filter),
            FieldFilterConflict(indicator: sequence.id, name: "Sequence", step: "closed", filter: filter),
        ])
        XCTAssertEqual(conflicts.map(\.explanation), [
            "“Read and closed” can't match: it needs the unmodified close of a file.",
            "“Sequence” can't complete: its step closed needs the unmodified close of a file.",
        ])
        XCTAssertEqual(FieldFilter.conflicts(of: [], with: [rule, sequence]), [])
        XCTAssertEqual(Set(conflicts).count, conflicts.count, "Each can be told apart, as Settings lists them")
    }

    /// An unordered sequence completes on some of its steps (`atLeast`). It's warned about only when the steps
    /// that still have events to match are too few, and then each starved step is named.
    func testAnUnorderedSequenceIsWarnedAboutOnlyWhenTooFewStepsAreLeft() {
        let unmodified = "event.close != nil AND event.close.modified == NO"
        let steps = [IndicatorSequence.Step(name: "ran", predicate: "event.exec != nil"),
                     IndicatorSequence.Step(name: "opened", predicate: "event.open != nil"),
                     IndicatorSequence.Step(name: "closed", predicate: unmodified)]
        let by = ["process.audit_token.pid"]
        let sequence = { (atLeast: Int) in
            self.sequenceIndicator(IndicatorSequence(order: .unordered, within: 5, by: by, atLeast: atLeast,
                                                     steps: steps))
        }
        XCTAssertEqual(FieldFilter.conflicts(of: [filter], with: [sequence(2)]), [])
        XCTAssertEqual(FieldFilter.conflicts(of: [filter], with: [sequence(3)]).map(\.step), ["closed"])
        XCTAssertEqual(FieldFilter.conflicts(of: [filter], with: Indicator.defaults), [], "None of Mac Monitor's own")
    }

    /// `macmonitor stream` says the same of the filters the Security Extension applied, and how to see every close.
    func testTheStreamsWarning() {
        let rule = ownIndicator("Read and closed", "event.close != nil AND event.close.modified == NO")
        XCTAssertEqual(StreamCommand.starvedIndicators(echoed: [filter.rawValue], indicators: [rule]), [
            "macmonitor: “Read and closed” can't match: it needs the unmodified close of a file. --every close shows "
                + "every close.",
        ])
        XCTAssertEqual(StreamCommand.starvedIndicators(echoed: [], indicators: [rule]), [])
        XCTAssertEqual(StreamCommand.starvedIndicators(echoed: nil, indicators: [rule]), [])
    }
}
