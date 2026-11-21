//
//  SequencePerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/15/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Sequences
/// Times what sequences cost an event (``SequenceTable``) whose steps match: each event of a chain that opens and
/// completes, ordered and unordered, with a later step on another lane handed over first, and of a table past its cap,
/// dropping its oldest chain for each new one.
/// `IndicatorPerformanceTests` times the shipped rules with sequences beside them, on events that match no step.
///
/// | Benchmark | Budget |
/// |---|---|
/// | `indicators.sequence.ordered` | ≤ 2 µs: half the events open a chain, half complete one |
/// | `indicators.sequence.crosslane` | ≤ 3 µs: an exec opens a chain, its process's write completes it |
/// | `indicators.sequence.early` | ≤ 3 µs: as crosslane, the writes handed over first and kept as early steps |
///
/// The crosslane and early benchmarks' sequence runs on two lanes, an exec then the new process's write, so an exec's
/// record is read for its key: steps all on one lane, as the download's are, keep no early steps.
/// | `indicators.sequence.unordered` | ≤ 2 µs: a chain opens, grows, and completes on its third event |
/// | `indicators.sequence.evicting` | ≤ 3 µs: every event opens a chain, and the table drops its oldest |
final class SequencePerformanceTests: PerformanceTestCase {
    /// Events per sample.
    private static let events = 10_000
    /// How many indicators Mac Monitor ships, which the shipped benchmark's name says.
    private static let shipped = Indicator.defaults.count

    /// A pack's sequence: a Mach-O written, then made executable.
    static func download() throws -> Indicator {
        try JSONDecoder().decode(Indicator.self, from: Data(IndicatorSequenceTests.packEntry.utf8))
    }

    /// One process writing three kinds of file.
    static let threeKinds = Indicator(name: "Three kinds", description: "", symbol: "star", color: .blue,
                                             rule: .sequence(SequenceEngineTests.unordered()))

    /// A download, then its chmod, for distinct files: every event a step match.
    func testOrdered() throws {
        let fixture = try recordedEvents(SequenceEngineTests.download)
        let messages = (0..<Self.events / 2).flatMap { index -> [Message] in
            var write = fixture[0], chmod = fixture[1]
            (write.target_path, chmod.target_path) = ("/tmp/download/\(index)", "/tmp/download/\(index)")
            return [write, chmod]
        }
        try time("indicators.sequence.ordered", CompiledIndicators([try Self.download()]), messages,
                 completing: Self.events / 2)
    }

    /// A program run, then a file the new process writes, within 5 seconds: steps on two lanes.
    ///
    /// - Returns: The sequence.
    static func runThenWrite() -> Indicator {
        let joined = IndicatorSequence.Step(
            name: "write", predicate: SequenceEngineTests.written.predicate,
            join: [IndicatorSequence.Join(field: "process.audit_token.pid", step: "run",
                                          stepField: "event.exec.target.audit_token.pid")])
        return Indicator(name: "Run then write", description: "", symbol: "star", color: .blue,
                         rule: .sequence(IndicatorSequence(order: .ordered, within: 5, steps: [
                             IndicatorSequence.Step(name: "run", predicate: "event.exec != nil"), joined,
                         ])))
    }

    /// Execs and the new processes' writes, for distinct processes, the write a second after its exec.
    ///
    /// - Parameter writeFirst: Hand each write over before its exec, as a process lane behind would.
    /// - Returns: The events.
    private func runsAndWrites(writeFirst: Bool) throws -> [Message] {
        let write = try recordedEvents(SequenceEngineTests.download)[0]
        let exec = try importRecord(try esloggerExec(parent: (1, 1)))
        return (0..<Self.events / 2).flatMap { index -> [Message] in
            var (written, run) = (write, exec)
            written.process.audit_token?.pid = Int32(index)
            written.message_darwin_time = exec.message_darwin_time + 1
            if case .exec(var event) = run.event {
                event.target.audit_token?.pid = Int32(index)
                run.event = .exec(event)
            }
            return writeFirst ? [written, run] : [run, written]
        }
    }

    /// An exec, then its process's write, in order, for distinct processes: every event a step match, on two lanes.
    func testCrossLane() throws {
        try time("indicators.sequence.crosslane", CompiledIndicators([Self.runThenWrite()]),
                 try runsAndWrites(writeFirst: false), completing: Self.events / 2)
    }

    /// The same with each write handed over before its exec, which a lane behind holds: the writes are kept as early
    /// steps, and each exec takes one.
    func testEarly() throws {
        try time("indicators.sequence.early", CompiledIndicators([Self.runThenWrite()]),
                 try runsAndWrites(writeFirst: true), completing: Self.events / 2)
    }

    /// One process at a time writing a PDF, a text file and a key: every event a step match.
    func testUnordered() throws {
        let fixture = try recordedEvents(SequenceEngineTests.threeKinds)
        let messages = (0..<Self.events / 3).flatMap { index in
            fixture.map { message in
                var message = message
                message.process.audit_token?.pidversion = Int32(index)
                return message
            }
        }
        try time("indicators.sequence.unordered", CompiledIndicators([Self.threeKinds]), messages,
                 completing: Self.events / 3)
    }

    /// Downloads of distinct files past the table's cap, so each opens a chain and drops the oldest.
    func testEvicting() throws {
        let fixture = try recordedEvents(SequenceEngineTests.download)
        let compiled = CompiledIndicators([try Self.download()])
        compiled.sequences[0].table.limit(to: Self.events / 10)
        let messages = (0..<Self.events).map { index in
            var write = fixture[0]
            write.target_path = "/tmp/download/\(index)"
            return write
        }
        try time("indicators.sequence.evicting", compiled, messages, completing: 0)
        XCTAssertEqual(compiled.openChains, Self.events / 10)
    }

    /// Time a set on events, each sample from no open chains, and check how many chains they complete.
    ///
    /// - Parameters:
    ///   - name: The benchmark's name.
    ///   - compiled: The set.
    ///   - messages: The events.
    ///   - completing: How many chains they complete.
    /// - Throws: The error writing the results, or a failure when they complete another number.
    private func time(_ name: String, _ compiled: CompiledIndicators, _ messages: [Message],
                      completing: Int) throws {
        var values = MessageValueCache()
        try benchmark(name, operations: messages.count, setUp: { compiled.forgetChains() }) { _ in
            var hits = 0
            for message in messages { hits += compiled.hits(for: message, values: &values).count }
            guard hits == completing else { throw BenchmarkFailure("\(hits) chains completed, not \(completing)") }
        }
        print(String(format: "[performance] %@: %d events, %d open chains after the last sample", name,
                     messages.count, compiled.openChains))
    }
}
