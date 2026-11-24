//
//  SequenceEngineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
import os
@testable import SutroESFramework


// MARK: - Sequences
/// Pins the Security Extension's sequences (``SequenceTable``): what completes an ordered chain and an unordered one,
/// the window, order by event time, `by` and joins, that only the completing event is tagged and a completed chain is
/// gone, and the hit's place among the event's others. The fixtures are recordings of `macmonitor stream`.
final class SequenceEngineTests: XCTestCase {
    /// curl closes a Mach-O it wrote, then chmod makes the file executable a second later.
    static let download = "sequence-file-made-executable.jsonl"
    /// One adhoc signed process overwrites a PDF, a text file and an SSH private key, within half a second.
    static let threeKinds = "sequence-three-kinds-written.jsonl"

    /// A file written and closed.
    static let written = IndicatorSequence.Step(name: "write",
                                                predicate: #"event.close != nil AND event.close.modified == YES"#)
    /// The same file's mode changed.
    static let changed = IndicatorSequence.Step(
        name: "chmod", predicate: "event.setmode != nil",
        join: [IndicatorSequence.Join(field: "target_path", step: "write", stepField: "target_path")])
    /// The kinds of file the unordered sequence's steps write, by the ending of each's path.
    static let kinds = [("pdf", ".pdf"), ("text", ".txt"), ("key", "id_ed25519"), ("source", ".swift")]

    /// A file written, then made executable.
    ///
    /// - Parameter within: Its window.
    /// - Returns: The sequence.
    static func ordered(within: Int = 5) -> IndicatorSequence {
        IndicatorSequence(order: .ordered, within: within, steps: [written, changed])
    }

    /// One process writing files of several kinds.
    ///
    /// - Parameters:
    ///   - atLeast: How many kinds.
    ///   - within: Its window.
    ///   - by: What ties the steps.
    /// - Returns: The sequence.
    static func unordered(atLeast: Int = 3, within: Int = 120,
                          by: [String] = ["process.audit_token.pid", "process.audit_token.pidversion"])
        -> IndicatorSequence {
        IndicatorSequence(order: .unordered, within: within, by: by, atLeast: atLeast, steps: kinds.map { name, end in
            IndicatorSequence.Step(name: name, predicate: #"event.close != nil AND target_path ENDSWITH "\#(end)""#)
        })
    }

    /// The download's chmod completes the chain, and only it is tagged. The chain is gone once it's complete.
    func testAnOrderedChainCompletesOnItsLastStep() throws {
        let sequence = sequenceIndicator(Self.ordered())
        let compiled = CompiledIndicators([sequence])
        XCTAssertEqual(compiled.count, 1)
        XCTAssertEqual(matchingLines(compiled, try recordedEvents(Self.download), matching: sequence.id), [2])
        XCTAssertEqual(compiled.openChains, 0)
    }

    /// A join that disagrees, a step past the window, steps the wrong way round, and a step whose time is before the
    /// step it follows, complete nothing. Both steps are on the file lane, which hands them over in Endpoint
    /// Security's order, so a chmod that comes before its write is never kept for it (``SequenceLateStepTests``).
    func testAnOrderedChainNeedsItsJoinWindowAndOrder() throws {
        let sequence = sequenceIndicator(Self.ordered())
        let messages = try recordedEvents(Self.download)
        var elsewhere = messages[1]
        elsewhere.target_path = "/Users/user/elsewhere"
        let cases: [(String, [Message])] = [
            ("another file", [messages[0], elsewhere]),
            ("past the window", [messages[0], moved(messages[1], by: 4.5)]),
            ("the wrong way round", [messages[1], messages[0]]),
            ("before the step it follows", [messages[0], moved(messages[1], by: -2)]),
        ]
        for (name, messages) in cases {
            XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), messages, matching: sequence.id), [], name)
        }
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), [messages[0], moved(messages[1], by: 3.9)],
                                     matching: sequence.id), [2], "within the window")
    }

    /// A second chmod completes nothing more, and a file written again restarts its chain, whose window is the newer
    /// write's.
    func testAChainIsConsumedAndANewerFirstStepReplacesIt() throws {
        let sequence = sequenceIndicator(Self.ordered())
        let messages = try recordedEvents(Self.download)
        let twice = [messages[0], messages[1], moved(messages[1], by: 0.5)]
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), twice, matching: sequence.id), [2])
        let rewritten = [messages[0], moved(messages[0], by: 4), moved(messages[1], by: 7)]
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), rewritten, matching: sequence.id), [3])
    }

    /// One process writing a PDF, a text file and a key completes 3 of 4 kinds on the third, whatever their order.
    /// Four kinds, three PDFs, or another process's file, don't.
    func testAnUnorderedChainCompletesAtLeastItsSteps() throws {
        let sequence = sequenceIndicator(Self.unordered()), every = sequenceIndicator(Self.unordered(atLeast: 4))
        let messages = try recordedEvents(Self.threeKinds)
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), messages, matching: sequence.id), [3])
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), messages.reversed(), matching: sequence.id), [3])
        XCTAssertEqual(matchingLines(CompiledIndicators([every]), messages, matching: every.id), [])
        let pdfs = messages.enumerated().map { index, message in
            var message = message
            message.target_path = "/Users/user/Documents/q\(index).pdf"
            return message
        }
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), pdfs, matching: sequence.id), [])
        var other = messages
        other[1].process.audit_token?.pidversion += 1
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), other, matching: sequence.id), [])
    }

    /// An unordered window slides: a step that matched longer ago than the window doesn't count, and the same step
    /// matched again does.
    func testAnUnorderedWindowSlides() throws {
        let sequence = sequenceIndicator(Self.unordered())
        let messages = try recordedEvents(Self.threeKinds)
        let spread = [messages[0], moved(messages[1], by: 100), moved(messages[2], by: 200),
                      moved(messages[0], by: 210)]
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), spread, matching: sequence.id), [4])
    }

    /// An event missing a `by` value ties nothing: an ad hoc signed process has no team ID.
    func testAMissingValueTiesNothing() throws {
        let sequence = sequenceIndicator(Self.unordered(by: ["process.team_id"]))
        let compiled = CompiledIndicators([sequence])
        XCTAssertEqual(matchingLines(compiled, try recordedEvents(Self.threeKinds), matching: sequence.id), [])
        XCTAssertEqual(compiled.openChains, 0)
    }

    /// A sequence's hit takes its place among the event's other hits in the set's order.
    func testTheHitIsInTheSetsOrder() throws {
        let rule = { Indicator(name: "Rule", description: "", symbol: "star", color: .blue,
                               predicate: "event.setmode != nil") }
        let before = rule(), sequence = sequenceIndicator(Self.ordered()), after = rule()
        let compiled = CompiledIndicators([before, sequence, after])
        XCTAssertEqual(compiled.count, 3)
        var values = MessageValueCache()
        let messages = try recordedEvents(Self.download)
        XCTAssertEqual(compiled.hits(for: messages[0], values: &values), [])
        XCTAssertEqual(compiled.hits(for: messages[1], values: &values).map(\.id), [before.id, sequence.id, after.id])
    }

    /// A step that doesn't compile, and a sequence that doesn't hold together, are problems, said as Settings says
    /// them, the sequence's off too. Neither runs.
    func testSequencesThatCantRun() throws {
        let untyped = IndicatorSequence(order: .ordered, within: 5, steps: [
            Self.written, IndicatorSequence.Step(name: "chmod", predicate: "process.pid > 1", join: Self.changed.join),
        ])
        var off = sequenceIndicator(untyped)
        off.isEnabled = false
        let unkeyed = sequenceIndicator(IndicatorSequence(order: .unordered, within: 5, steps: Self.unordered().steps))
        let compiled = CompiledIndicators([off, unkeyed])
        XCTAssertEqual(compiled.count, 0)
        XCTAssertEqual(compiled.problems.map(\.id), [off.id, unkeyed.id])
        XCTAssertTrue(compiled.problems[0].reason.hasPrefix("The step chmod: It doesn't name its event types"),
                      compiled.problems[0].reason)
        XCTAssertTrue(compiled.problems[1].reason.hasPrefix("An unordered sequence needs by"),
                      compiled.problems[1].reason)
    }

    /// Stamping an event deferring its steps, as the exec lane does, advances nothing, and advancing them on its turn
    /// puts the sequence's hit among the event's others, in the set's order.
    func testDeferredStepsAdvanceOnTheirTurn() throws {
        let sequence = sequenceIndicator(Self.ordered())
        let rule = ownIndicator("Any chmod", "event.setmode != nil")
        let compiled = CompiledIndicators([sequence, rule])
        var values = MessageValueCache()
        var messages = try recordedEvents(Self.download)
        let first = compiled.stamp(&messages[0], values: &values, deferringSteps: true)
        XCTAssertEqual(compiled.openChains, 0, "Deferred")
        compiled.advance(&messages[0], steps: first, values: &values, chains: nil)
        XCTAssertEqual(compiled.openChains, 1)
        let second = compiled.stamp(&messages[1], values: &values, deferringSteps: true)
        XCTAssertEqual(messages[1].indicators?.hits.map(\.id), [rule.id])
        compiled.advance(&messages[1], steps: second, values: &values, chains: nil)
        XCTAssertEqual(messages[1].indicators?.hits.map(\.id), [sequence.id, rule.id])
        XCTAssertEqual(compiled.openChains, 0)
    }

    /// A set made from another keeps its open chains for a sequence that didn't change, and starts over for one that
    /// did.
    func testANewSetKeepsTheChainsOfASequenceThatDidntChange() throws {
        let id = UUID()
        let old = CompiledIndicators([sequenceIndicator(Self.ordered(), id: id)])
        let messages = try recordedEvents(Self.download)
        var values = MessageValueCache()
        _ = old.hits(for: messages[0], values: &values)
        let same = CompiledIndicators([sequenceIndicator(Self.ordered(), id: id)], reusing: old)
        XCTAssertTrue(same.sequences[0].table === old.sequences[0].table)
        let changed = CompiledIndicators([sequenceIndicator(Self.ordered(within: 6), id: id)], reusing: old)
        XCTAssertEqual(matchingLines(changed, [messages[1]], matching: id), [])
        XCTAssertEqual(matchingLines(same, [messages[1]], matching: id), [1])
    }

    /// Past its cap, a table drops its oldest chains and counts them: the oldest write's chmod completes nothing, and
    /// the newest's still does.
    func testATableDropsItsOldestChainsPastItsCap() throws {
        let sequence = sequenceIndicator(Self.ordered())
        let compiled = CompiledIndicators([sequence])
        compiled.sequences[0].table.limit(to: 4)
        let messages = try recordedEvents(Self.download)
        let writes = (0..<6).map { index in
            var write = moved(messages[0], by: Double(index) / 10)
            write.target_path = "/tmp/file\(index)"
            return write
        }
        var values = MessageValueCache()
        for write in writes { _ = compiled.hits(for: write, values: &values) }
        XCTAssertEqual(compiled.openChains, 4)
        XCTAssertEqual(compiled.sequences[0].table.evictions, 2)
        let chmod = { (index: Int) -> Message in
            var chmod = self.moved(messages[1], by: -0.4)
            chmod.target_path = "/tmp/file\(index)"
            return chmod
        }
        XCTAssertEqual(matchingLines(compiled, [chmod(0), chmod(5)], matching: sequence.id), [2])
    }

    /// Lanes advancing one table at once complete every chain, once each.
    func testLanesShareATable() throws {
        let sequence = sequenceIndicator(Self.ordered())
        let compiled = CompiledIndicators([sequence])
        let messages = try recordedEvents(Self.download)
        let lanes = 8, pairs = 500
        let completed = OSAllocatedUnfairLock(initialState: 0)
        DispatchQueue.concurrentPerform(iterations: lanes) { lane in
            var values = MessageValueCache(), count = 0
            for pair in 0..<pairs {
                var write = messages[0], chmod = messages[1]
                (write.target_path, chmod.target_path) = ("/tmp/\(lane)/\(pair)", "/tmp/\(lane)/\(pair)")
                _ = compiled.hits(for: write, values: &values)
                count += compiled.hits(for: chmod, values: &values).count
            }
            let total = count
            completed.withLock { $0 += total }
        }
        XCTAssertEqual(completed.withLock { $0 }, lanes * pairs)
        XCTAssertEqual(compiled.openChains, 0)
    }
}


// MARK: - Recorded events
extension XCTestCase {
    /// - Parameters:
    ///   - sequence: A sequence.
    ///   - id: Its identity.
    /// - Returns: Its indicator.
    func sequenceIndicator(_ sequence: IndicatorSequence, id: UUID = UUID()) -> Indicator {
        Indicator(id: id, name: "Sequence", description: "", symbol: "star", color: .blue, rule: .sequence(sequence))
    }

    /// Evaluate events in order, as one lane would.
    ///
    /// - Parameters:
    ///   - compiled: The set.
    ///   - messages: The events.
    ///   - id: An indicator.
    /// - Returns: The lines, from 1, whose events it matched.
    func matchingLines(_ compiled: CompiledIndicators, _ messages: [Message], matching id: UUID) -> [Int] {
        var values = MessageValueCache()
        return messages.indices.filter { compiled.hits(for: messages[$0], values: &values).contains { $0.id == id } }
            .map { $0 + 1 }
    }

    /// - Parameters:
    ///   - message: An event.
    ///   - seconds: How long after its time to move it.
    /// - Returns: The event, at its new time.
    func moved(_ message: Message, by seconds: Double) -> Message {
        var message = message
        message.message_darwin_time += seconds
        return message
    }

    /// - Parameter name: A JSONL fixture.
    /// - Returns: Its events, each read as Open Trace reads it.
    func recordedEvents(_ name: String) throws -> [Message] {
        let reader = try TraceRecordReader(url: try fixtureURL(name))
        var messages: [Message] = []
        while let record = try reader.next() {
            guard case .object(let data, _) = record else { continue }
            messages.append(try TraceImporter.message(from: data))
        }
        return messages
    }
}
