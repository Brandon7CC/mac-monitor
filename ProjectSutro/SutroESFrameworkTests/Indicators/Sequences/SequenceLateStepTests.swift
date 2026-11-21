//
//  SequenceLateStepTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Steps out of order
/// Pins an ordered sequence whose steps run on more than one lane, which hand them over out of time order: an exec
/// on the process lane, then the new process's writes and chmods on the file lane. A later step that comes first is
/// kept as an early step, and the step it follows completes the chain as it comes, in time order and within the
/// window only, never with two steps from one event, and for ``SequenceChains/lateness`` only. A step handed over late
/// finds the chain it follows in time among those waiting, a chain a later-started one replaced advances only with
/// earlier steps, a chain is kept past its window for the lateness, early steps never drop a waiting chain, and steps
/// all on one lane keep no early steps.
final class SequenceLateStepTests: XCTestCase {
    /// The new process's pid.
    private let pid: Int32 = 4_242
    /// The file the process writes.
    private let tool = "/tmp/tool"

    /// A program run.
    private static let run = IndicatorSequence.Step(name: "run", predicate: "event.exec != nil")
    /// A file the new process writes.
    private static let write = IndicatorSequence.Step(
        name: "write", predicate: SequenceEngineTests.written.predicate,
        join: [IndicatorSequence.Join(field: "process.audit_token.pid", step: "run",
                                      stepField: "event.exec.target.audit_token.pid")])
    /// The written file's mode changed.
    private static let chmod = IndicatorSequence.Step(
        name: "chmod", predicate: "event.setmode != nil",
        join: [IndicatorSequence.Join(field: "target_path", step: "write", stepField: "target_path")])

    /// A program run, then a file it writes, within 5 seconds.
    private let runThenWrite = IndicatorSequence(order: .ordered, within: 5, steps: [run, write])
    /// A program run, then a file it writes and makes executable, within 5 seconds.
    private let runWriteChmod = IndicatorSequence(order: .ordered, within: 5, steps: [run, write, chmod])

    /// An exec, and the download fixture's close and chmod.
    private var exec: Message!, close: Message!, setmode: Message!

    /// Read the events.
    ///
    /// - Throws: The error reading them.
    override func setUpWithError() throws {
        exec = try importRecord(try esloggerExec(parent: (1, 1)))
        let download = try recordedEvents(SequenceEngineTests.download)
        (close, setmode) = (download[0], download[1])
    }

    /// The program run in a process.
    ///
    /// - Parameters:
    ///   - pid: The process's pid.
    ///   - time: Its time, in seconds after the close's.
    /// - Returns: The exec.
    private func run(_ pid: Int32, at time: Double) -> Message {
        var message: Message = exec
        if case .exec(var event) = message.event {
            event.target.pid = pid
            event.target.audit_token?.pid = pid
            message.event = .exec(event)
        }
        message.process.audit_token?.pid = pid
        message.message_darwin_time = close.message_darwin_time + time
        return message
    }

    /// A file event of a process's.
    ///
    /// - Parameters:
    ///   - message: The close or the chmod.
    ///   - pid: The process's pid.
    ///   - path: The file.
    ///   - time: Its time, in seconds after the close's.
    /// - Returns: The event.
    private func file(_ message: Message, by pid: Int32, _ path: String, at time: Double) -> Message {
        var message = message
        message.process.audit_token?.pid = pid
        message.target_path = path
        message.message_darwin_time = close.message_darwin_time + time
        return message
    }

    /// A process's write.
    private func write(_ pid: Int32, _ path: String, at time: Double) -> Message {
        file(close, by: pid, path, at: time)
    }

    /// A process's chmod.
    private func chmod(_ pid: Int32, _ path: String, at time: Double) -> Message {
        file(setmode, by: pid, path, at: time)
    }

    /// - Parameters:
    ///   - sequence: A sequence.
    ///   - messages: Events, as lanes hand them over.
    /// - Returns: The lines that complete it, each from 1.
    private func lines(_ sequence: IndicatorSequence, _ messages: [Message]) -> [Int] {
        let indicator = sequenceIndicator(sequence)
        return matchingLines(CompiledIndicators([indicator]), messages, matching: indicator.id)
    }

    /// A write handed over before the exec it follows, as the process lane is behind, completes the chain as the exec
    /// comes, and the exec is tagged. A write from before the exec, past its window, or of another process completes
    /// nothing.
    func testALaterStepCanComeFirst() throws {
        let indicator = sequenceIndicator(runThenWrite)
        let compiled = CompiledIndicators([indicator])
        XCTAssertEqual(compiled.sequences[0].table.program.arrivesEarly, [false, true])
        XCTAssertEqual(matchingLines(compiled, [write(pid, tool, at: 1), run(pid, at: 0)], matching: indicator.id), [2])
        XCTAssertEqual(compiled.openChains, 0, "The write was taken")
        let cases: [(String, [Message])] = [
            ("before the exec", [write(pid, tool, at: 0), run(pid, at: 1)]),
            ("past the window", [write(pid, tool, at: 6), run(pid, at: 0)]),
            ("another process", [write(pid + 1, tool, at: 1), run(pid, at: 0)]),
        ]
        for (name, messages) in cases {
            XCTAssertEqual(lines(runThenWrite, messages), [], name)
        }
    }

    /// Every later step can come before the exec: the write and the chmod, then the exec, which completes the chain.
    func testEveryLaterStepCanComeFirst() throws {
        XCTAssertEqual(lines(runWriteChmod, [write(pid, tool, at: 1), chmod(pid, tool, at: 2), run(pid, at: 0)]), [3])
    }

    /// A chain that comes late takes the earliest early step that follows it, as time order would: of two writes
    /// and a chmod handed over before the exec, the first write, then its chmod. An unrelated write from before the
    /// exec is passed over for the one after it.
    func testALateChainTakesTheEarliestStepThatFollows() throws {
        let early = [write(pid, tool, at: 0.1), chmod(pid, tool, at: 0.2), write(pid, "/tmp/other", at: 0.3)]
        XCTAssertEqual(lines(runWriteChmod, early + [run(pid, at: 0)]), [4])
        for writes in [[0.0, 3], [3, 0]] {
            let messages = writes.map { write(pid, tool, at: $0) } + [run(pid, at: 2)]
            XCTAssertEqual(lines(runThenWrite, messages), [3], "\(writes)")
        }
    }

    /// A chain that comes late never takes two steps from one event: a close that's both the write and the rewrite
    /// completes nothing with the exec, and the next close does.
    func testALateChainTakesOneStepFromEachEvent() throws {
        let rewrite = IndicatorSequence.Step(name: "rewrite", predicate: Self.write.predicate, join: Self.write.join)
        let sequence = IndicatorSequence(order: .ordered, within: 5, steps: [Self.run, Self.write, rewrite])
        XCTAssertEqual(lines(sequence, [write(pid, tool, at: 1), run(pid, at: 0)]), [])
        XCTAssertEqual(lines(sequence, [write(pid, tool, at: 1), run(pid, at: 0), write(pid, tool, at: 2)]), [3])
        XCTAssertEqual(lines(sequence, [run(pid, at: 0), write(pid, tool, at: 1)]), [], "In order, as before")
    }

    /// A step handed over late finds the chain it follows in time among those waiting, though later ones started
    /// since: a process's writes at 0.05, 0.15 and 0.25 come first, and its exec at 0.10, held for Launch Services,
    /// completes the chain the first write started.
    func testALateStepFindsTheChainItFollows() throws {
        let written = IndicatorSequence.Step(name: "write", predicate: SequenceEngineTests.written.predicate)
        let ran = IndicatorSequence.Step(name: "run", predicate: "event.exec != nil")
        let sequence = IndicatorSequence(order: .ordered, within: 5, by: ["process.audit_token.pid"],
                                         steps: [written, ran])
        let writes = [0.05, 0.15, 0.25].map { write(pid, tool, at: $0) }
        XCTAssertEqual(lines(sequence, writes + [run(pid, at: 0.1)]), [4])
        XCTAssertEqual(lines(sequence, writes + [run(pid, at: 0.01)]), [], "Before every write")
    }

    /// A chain that a later-started one took the key from, in time order, advances only with a step from before then:
    /// two execs of one process, then two writes, all in order, tag the first write only. A chain that comes to a key
    /// after a later-started one did never waits there: two execs, each process writing one file, then two chmods of
    /// it, tag the first chmod only.
    func testAReplacedChainAdvancesOnlyWithEarlierSteps() throws {
        let twice = [run(pid, at: 0), run(pid, at: 0.01), write(pid, tool, at: 1), write(pid, tool, at: 2)]
        XCTAssertEqual(lines(runThenWrite, twice), [3])
        let crossed = [run(pid, at: 0), run(pid + 1, at: 0.2), write(pid + 1, tool, at: 0.3), write(pid, tool, at: 0.5),
                       chmod(pid, tool, at: 1), chmod(pid, tool, at: 2)]
        XCTAssertEqual(lines(runWriteChmod, crossed), [5])
    }

    /// A chain that started later and comes late can take a step an earlier-started chain took first, as time order
    /// would have given it to the later one: a process writes /tmp/a, then /tmp/b, then runs something, then /tmp/b
    /// is made executable. Whether the run comes before the writes or between them, the chmod completes the chain
    /// /tmp/b's write started.
    func testALateChainTakesAStepAnEarlierChainTook() throws {
        let written = IndicatorSequence.Step(name: "write", predicate: SequenceEngineTests.written.predicate)
        let ran = IndicatorSequence.Step(name: "run", predicate: "event.exec != nil", join: [
            IndicatorSequence.Join(field: "process.audit_token.pid", step: "write",
                                   stepField: "process.audit_token.pid"),
        ])
        let made = IndicatorSequence.Step(name: "chmod", predicate: "event.setmode != nil", join: [
            IndicatorSequence.Join(field: "target_path", step: "write", stepField: "target_path"),
        ])
        let sequence = IndicatorSequence(order: .ordered, within: 60, steps: [written, ran, made])
        let (first, second) = (write(pid, "/tmp/a", at: 10), write(pid, "/tmp/b", at: 10.2))
        let (spawn, executable) = (run(pid, at: 10.4), chmod(pid, "/tmp/b", at: 10.6))
        for (name, messages) in [("in time order", [first, second, spawn, executable]),
                                 ("the run first", [spawn, first, second, executable]),
                                 ("the second write late", [first, spawn, second, executable])] {
            XCTAssertEqual(lines(sequence, messages), [4], name)
        }
    }

    /// A chain is kept past its window for the lateness, so a lane behind still completes it: the exec at 0, another
    /// process's exec at 12 from a lane ahead, then the write at 4. Past the lateness it's gone.
    func testAChainOutlivesItsWindowForLateSteps() throws {
        for (ahead, expected) in [(12.0, [3]), (5 + SequenceChains.lateness + 1, [])] {
            let messages = [run(pid, at: 0), run(pid + 1, at: ahead), write(pid, tool, at: 4)]
            XCTAssertEqual(lines(runThenWrite, messages), expected, "A lane \(ahead) seconds ahead")
        }
    }

    /// An early step is kept for the lateness only: a write at 5 waits while the latest event is less than the
    /// lateness past it, and is gone, with nothing completed, once it's more.
    func testAnEarlyStepIsKeptForTheLatenessOnly() throws {
        let indicator = sequenceIndicator(runThenWrite)
        let first = CompiledIndicators([indicator])
        XCTAssertEqual(matchingLines(first, [write(pid, tool, at: 5)], matching: indicator.id), [])
        XCTAssertEqual(first.sequences[0].table.earlySteps, 1)
        for (ahead, expected) in [(5 + SequenceChains.lateness - 1, [3]), (5 + SequenceChains.lateness + 1, [])] {
            let messages = [write(pid, tool, at: 5), run(pid + 1, at: ahead), run(pid, at: 4)]
            XCTAssertEqual(lines(runThenWrite, messages), expected, "The latest \(ahead) seconds in")
        }
    }

    /// Early steps have a cap of their own, so a burst of them never drops a waiting chain: an exec, then writes by
    /// twenty other processes, more than the early steps' cap, then the process's own write, which completes it.
    func testEarlyStepsNeverDropAWaitingChain() throws {
        let indicator = sequenceIndicator(runThenWrite)
        let compiled = CompiledIndicators([indicator])
        let table = compiled.sequences[0].table
        table.limit(to: 16)
        let burst = (1...20).map { write(pid + Int32($0), "/tmp/\($0)", at: 0.5) }
        let messages = [run(pid, at: 0)] + burst + [write(pid, tool, at: 1)]
        XCTAssertEqual(matchingLines(compiled, messages, matching: indicator.id), [22])
        XCTAssertEqual(table.evictions, 0)
        XCTAssertEqual(table.earlySteps, SequenceChains.earlyCapacity(16))
        XCTAssertEqual(table.earlyDrops, 20 - SequenceChains.earlyCapacity(16))
    }

    /// Steps all on one lane come in time order, so none is kept early: the download's chmod handed over before its
    /// write completes nothing and keeps nothing, as that lane never hands them over so.
    func testStepsOnOneLaneKeepNoEarlySteps() throws {
        let indicator = sequenceIndicator(SequenceEngineTests.ordered())
        let compiled = CompiledIndicators([indicator])
        XCTAssertEqual(compiled.sequences[0].table.program.arrivesEarly, [false, false])
        XCTAssertEqual(matchingLines(compiled, [chmod(pid, tool, at: 1), write(pid, tool, at: 0)],
                                     matching: indicator.id), [])
        XCTAssertEqual(compiled.sequences[0].table.earlySteps, 0)
    }
}
