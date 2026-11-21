//
//  SequenceEngineEdgeTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Sequences at their edges
/// Pins what ``SequenceEngineTests`` doesn't: a chain of three steps, which chain stays where two would wait under
/// one key, an unordered window around an event a lane hands over late or after the clock went back, one event
/// that matches two steps, the rebase of a long-lived chain, the line's length, and each set's share of chains.
final class SequenceEngineEdgeTests: XCTestCase {
    /// The download fixture's close and chmod.
    private func download() throws -> (close: Message, chmod: Message) {
        let events = try recordedEvents(SequenceEngineTests.download)
        return (events[0], events[1])
    }

    /// - Parameters:
    ///   - message: An event.
    ///   - path: Its target path.
    ///   - time: Its time, in seconds after `base`.
    ///   - base: The event to time it from.
    ///   - process: The event whose process it gets, if any.
    /// - Returns: The event, changed.
    private func event(_ message: Message, _ path: String, at time: Double, after base: Message,
                       process: Message? = nil) -> Message {
        var message = message
        message.target_path = path
        message.message_darwin_time = base.message_darwin_time + time
        if let process { message.process = process.process }
        return message
    }

    /// A third step that joins to the first completes the chain on its own file only, so the first step's value
    /// outlives the second. The completing close starts another chain too, as it's a first step as well. Every step
    /// is on the file lane, so none is kept as an early step.
    func testAThirdStepJoinsToTheFirst() throws {
        let join = [IndicatorSequence.Join(field: "target_path", step: "write", stepField: "target_path")]
        let rewrite = IndicatorSequence.Step(name: "rewrite", predicate: SequenceEngineTests.written.predicate,
                                             join: join)
        let sequence = sequenceIndicator(IndicatorSequence(order: .ordered, within: 5, steps: [
            SequenceEngineTests.written, SequenceEngineTests.changed, rewrite,
        ]))
        let (close, chmod) = try download()
        let same = [close, chmod, event(close, close.target_path!, at: 2, after: close)]
        let compiled = CompiledIndicators([sequence])
        XCTAssertEqual(matchingLines(compiled, same, matching: sequence.id), [3])
        XCTAssertEqual(compiled.openChains, 1)
        XCTAssertEqual(compiled.sequences[0].table.earlySteps, 0)
        let other = [close, chmod, event(close, "/tmp/other", at: 2, after: close)]
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), other, matching: sequence.id), [])
    }

    /// Where two chains would wait for one step under one key, the one that started later stays, whichever reached
    /// it first: one process writes two files, makes both executable, and finishes inside the later write's window.
    func testTheChainThatStartedLaterStays() throws {
        let finish = IndicatorSequence.Step(name: "finish",
                                            predicate: #"event.close != nil AND target_path ENDSWITH ".done""#)
        let write = IndicatorSequence.Step(name: "write", predicate: SequenceEngineTests.written.predicate
                                           + #" AND NOT target_path ENDSWITH ".done""#)
        let sequence = sequenceIndicator(IndicatorSequence(
            order: .ordered, within: 30, by: ["process.audit_token.pid", "process.audit_token.pidversion"],
            steps: [write, SequenceEngineTests.changed, finish]))
        let (close, chmod) = try download()
        let at = { (message: Message, path: String, time: Double) in
            self.event(message, path, at: time, after: close, process: close)
        }
        let writes = [at(close, "/tmp/a", 1), at(close, "/tmp/b", 10)], done = at(close, "/tmp/x.done", 35)
        for chmods in [[at(chmod, "/tmp/b", 11), at(chmod, "/tmp/a", 12)],
                       [at(chmod, "/tmp/a", 11), at(chmod, "/tmp/b", 12)]] {
            XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), writes + chmods + [done],
                                         matching: sequence.id), [5], chmods.map(\.target_path!).joined())
        }
    }

    /// An unordered window holds the event it's judged for: a step handed over late completes a chain only within
    /// the window of the steps it joins, and steps from before the clock went back don't count.
    func testAnUnorderedWindowHoldsItsEvent() throws {
        let sequence = sequenceIndicator(SequenceEngineTests.unordered(atLeast: 2, within: 5))
        let files = try recordedEvents(SequenceEngineTests.threeKinds)
        let cases: [(String, [Message], [Int])] = [
            ("handed over 30 seconds late", [moved(files[0], by: 30), files[1]], []),
            ("handed over 3 seconds late", [moved(files[0], by: 3), files[1]], [2]),
            ("after the clock went back", [moved(files[0], by: 1_000), files[1], files[2]], [3]),
        ]
        for (name, messages, lines) in cases {
            XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), messages, matching: sequence.id), lines, name)
        }
    }

    /// Every step an unordered chain completes with fits in one window: a PDF, a text file and a key 8 seconds apart,
    /// with a Swift file handed over late between them, complete nothing in 5 seconds, and four quick ones do.
    func testAnUnorderedChainFitsItsWindow() throws {
        let sequence = sequenceIndicator(SequenceEngineTests.unordered(atLeast: 4, within: 5))
        let files = try recordedEvents(SequenceEngineTests.threeKinds)
        let at = { (index: Int, path: String?, time: Double) -> Message in
            var file = files[index]
            if let path { file.target_path = path }
            file.message_darwin_time = files[0].message_darwin_time + time
            return file
        }
        let spread = [at(0, nil, 0), at(1, nil, 4), at(2, nil, 8), at(0, "/tmp/main.swift", 3.5)]
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), spread, matching: sequence.id), [])
        let quick = [at(0, nil, 0), at(1, nil, 1), at(2, nil, 2), at(0, "/tmp/main.swift", 3)]
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), quick, matching: sequence.id), [4])
    }

    /// An event a lane behind another hands over late drops no chain: not other keys' chains as it makes room, not
    /// the ordered chain it can't follow, and not the unordered chain whose earlier steps it still fits with.
    func testALateEventDropsNoChain() throws {
        let files = try recordedEvents(SequenceEngineTests.threeKinds), (close, chmod) = try download()
        let at = { (message: Message, path: String?, time: Double, process: Int32) -> Message in
            var message = message
            if let path { message.target_path = path }
            message.message_darwin_time = files[0].message_darwin_time + time
            message.process = files[0].process
            message.process.audit_token?.pidversion = process
            return message
        }
        let pair = sequenceIndicator(SequenceEngineTests.unordered(atLeast: 2, within: 5))
        let others = (0..<5).map { at(files[0], nil, 100 + Double($0) / 10, Int32($0)) }
        let late = at(files[1], nil, 88, 9), key = at(files[2], nil, 102, 1)
        XCTAssertEqual(matchingLines(CompiledIndicators([pair]), others + [late, key], matching: pair.id), [7],
                       "other keys")
        let ordered = sequenceIndicator(SequenceEngineTests.ordered())
        let downloads = [event(close, "/tmp/tool", at: 100, after: close),
                         event(chmod, "/tmp/tool", at: 90, after: close),
                         event(chmod, "/tmp/tool", at: 101, after: close)]
        XCTAssertEqual(matchingLines(CompiledIndicators([ordered]), downloads, matching: ordered.id), [3], "ordered")
        let three = sequenceIndicator(SequenceEngineTests.unordered(atLeast: 3, within: 5))
        let spread = [at(files[0], nil, 92, 0), at(files[1], nil, 96, 0), at(files[0], "/tmp/main.swift", 100, 0),
                      at(files[2], nil, 94.5, 0)]
        XCTAssertEqual(matchingLines(CompiledIndicators([three]), spread, matching: three.id), [4], "unordered")
        let lagging = [at(files[0], nil, 100, 0), at(files[1], nil, 93, 0), at(files[2], nil, 94, 0)]
        XCTAssertEqual(matchingLines(CompiledIndicators([pair]), lagging, matching: pair.id), [3],
                       "two late steps that share a window, less than the lateness behind")
    }

    /// An event more than 5 minutes behind the latest means the clock went back: the table forgets its chains, and
    /// the next ones complete.
    func testTheClockGoingBackForgetsChains() throws {
        let sequence = sequenceIndicator(SequenceEngineTests.ordered())
        let (close, chmod) = try download()
        let compiled = CompiledIndicators([sequence])
        let messages = [event(close, "/tmp/before", at: 3_600, after: close),
                        event(close, "/tmp/tool", at: 0, after: close), event(chmod, "/tmp/tool", at: 1, after: close)]
        XCTAssertEqual(matchingLines(compiled, messages, matching: sequence.id), [3])
        XCTAssertEqual(compiled.sequences[0].table.clockResets, 1)
        XCTAssertEqual(compiled.openChains, 0)
    }

    /// Settings and the Security Extension give a sequence with several problems the same reason.
    func testSettingsAndTheExtensionAgree() throws {
        let untyped = IndicatorSequence.Step(name: "run", predicate: "process.pid > 1")
        let sequence = sequenceIndicator(IndicatorSequence(
            order: .ordered, within: 5, by: ["event.exec.launched_by_parent.path"],
            steps: [SequenceEngineTests.written, untyped]))
        let reason = try XCTUnwrap(CompiledIndicators([sequence]).problems.first?.reason)
        XCTAssertEqual(reason, sequence.sensorProblem)
        XCTAssertTrue(reason.hasPrefix("The step run: It doesn't name its event types"), reason)
    }

    /// One event that matches two steps of an unordered chain counts once, and a second event makes two.
    func testOneEventCountsOnce() throws {
        let steps = ["alpha", "beta"].map { word in
            IndicatorSequence.Step(name: word, predicate: #"event.close != nil AND target_path CONTAINS "\#(word)""#)
        }
        let sequence = sequenceIndicator(IndicatorSequence(
            order: .unordered, within: 60, by: ["process.audit_token.pid", "process.audit_token.pidversion"],
            atLeast: 2, steps: steps))
        let (close, _) = try download()
        let both = event(close, "/tmp/alpha-beta", at: 0, after: close)
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), [both], matching: sequence.id), [])
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]),
                                     [both, event(close, "/tmp/alpha", at: 1, after: close)],
                                     matching: sequence.id), [2])
    }

    /// A chain that lives past twice its window and the lateness is rebased, and still judges each step by its own
    /// time: the first PDF has left the window, and a later one completes the chain.
    func testALongLivedUnorderedChain() throws {
        let sequence = sequenceIndicator(SequenceEngineTests.unordered())
        let files = try recordedEvents(SequenceEngineTests.threeKinds)
        let spread = [files[0], moved(files[1], by: 110), moved(files[1], by: 230), moved(files[2], by: 265)]
        XCTAssertGreaterThan(265.0, 2 * (120 + SequenceChains.lateness), "The key's event rebases the chain")
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), spread, matching: sequence.id), [])
        XCTAssertEqual(matchingLines(CompiledIndicators([sequence]), spread + [moved(files[0], by: 270)],
                                     matching: sequence.id), [5])
    }

    /// The line a table drops chains from stays near its chains' count, however many chains came and went.
    func testTheLineStaysShort() throws {
        let (close, _) = try download()
        let expiring = CompiledIndicators([sequenceIndicator(SequenceEngineTests.ordered())])
        let capped = CompiledIndicators([sequenceIndicator(SequenceEngineTests.ordered())])
        capped.sequences[0].table.limit(to: 64)
        var values = MessageValueCache()
        for index in 0..<10_000 {
            _ = expiring.hits(for: event(close, "/tmp/\(index)", at: Double(index), after: close), values: &values)
            _ = capped.hits(for: event(close, "/tmp/\(index)", at: 0, after: close), values: &values)
        }
        for (name, set) in [("expiring", expiring), ("capped", capped)] {
            let table = set.sequences[0].table
            XCTAssertLessThanOrEqual(table.lineLength, 2 * table.count + 65, name)
        }
        XCTAssertEqual(capped.openChains, 64)
        XCTAssertLessThanOrEqual(expiring.openChains, 6 + Int(SequenceChains.lateness), "Its window and the lateness")
    }

    /// Each set holds its own share of chains: one built beside the set in use, as a refused change is, leaves the
    /// set in use holding as many as before.
    func testEachSetHoldsItsOwnShare() throws {
        let id = UUID()
        let inUse = CompiledIndicators([sequenceIndicator(SequenceEngineTests.ordered(), id: id)])
        let crowded = CompiledIndicators([sequenceIndicator(SequenceEngineTests.ordered(), id: id)]
            + (0..<600).map { _ in sequenceIndicator(SequenceEngineTests.ordered()) }, reusing: inUse)
        XCTAssertTrue(crowded.sequences[0].table === inUse.sequences[0].table)
        XCTAssertEqual(inUse.chainShare, SequenceTable.totalChains)
        XCTAssertEqual(crowded.chainShare, SequenceTable.totalChains / 601)
        XCTAssertLessThanOrEqual(IndicatorLimits.maxIndicators * SequenceTable.minimumChains, SequenceTable.totalChains,
                                 "A set's shares can add up to more than the total")
        let (close, _) = try download()
        var values = MessageValueCache()
        for index in 0..<100 {
            _ = inUse.hits(for: event(close, "/tmp/\(index)", at: 0, after: close), values: &values)
        }
        XCTAssertEqual(inUse.openChains, 100)
        XCTAssertEqual(inUse.sequences[0].table.evictions, 0)
    }

    /// A record full of hits still advances every sequence the event matched a step of: one whose hit doesn't fit
    /// loses only that hit, a later sequence's chain still starts on the event, and the event counts once as capped.
    func testAFullRecordStillAdvancesEverySequence() throws {
        let rules = (0..<CompiledIndicators.hitLimit).map { ownIndicator("Close \($0)", "event.close != nil") }
        let chmodThenWrite = sequenceIndicator(IndicatorSequence(order: .ordered, within: 5, steps: [
            IndicatorSequence.Step(name: "chmod", predicate: "event.setmode != nil"),
            IndicatorSequence.Step(name: "write", predicate: SequenceEngineTests.written.predicate, join: [
                IndicatorSequence.Join(field: "target_path", step: "chmod", stepField: "target_path"),
            ]),
        ]))
        let madeExecutable = sequenceIndicator(SequenceEngineTests.ordered())
        let compiled = CompiledIndicators(rules + [chmodThenWrite, madeExecutable])
        let (close, chmod) = try download()
        let messages = [event(chmod, "/tmp/tool", at: 0, after: close), event(close, "/tmp/tool", at: 1, after: close),
                        event(chmod, "/tmp/tool", at: 2, after: close)]
        var values = MessageValueCache()
        let hits = messages.map { compiled.hits(for: $0, values: &values).map(\.id) }
        XCTAssertEqual(hits[1].count, CompiledIndicators.hitLimit)
        XCTAssertFalse(hits[1].contains(chmodThenWrite.id), "Its hit didn't fit")
        XCTAssertTrue(hits[2].contains(madeExecutable.id), "The download's chain started on the full record")
        XCTAssertEqual(values.cappedEvents, 1)
    }

    /// `indicators test` starts each recording with no open chains: a download in one file and its chmod in another
    /// complete nothing, and the two together do.
    func testEachReplayStartsWithNoChains() throws {
        let folder = try makeTemporaryDirectory()
        let lines = try String(contentsOf: try fixtureURL(SequenceEngineTests.download), encoding: .utf8)
            .split(separator: "\n")
        for (name, line) in [("close.jsonl", lines[0]), ("chmod.jsonl", lines[1])] {
            try Data((line + "\n").utf8).write(to: folder.appendingPathComponent(name))
        }
        let sequence = try JSONDecoder().decode(Indicator.self, from: Data(IndicatorSequenceTests.packEntry.utf8))
        var replay = IndicatorReplay([sequence]), matched: [Int] = []
        for name in ["close.jsonl", "chmod.jsonl"] {
            try replay.replay(folder.appendingPathComponent(name)) {
                if !$0.matched.isEmpty { matched.append($0.line) }
            }
        }
        XCTAssertEqual(matched, [])
        try replay.replay(try fixtureURL(SequenceEngineTests.download)) {
            if !$0.matched.isEmpty { matched.append($0.line) }
        }
        XCTAssertEqual(matched, [2])
    }
}
