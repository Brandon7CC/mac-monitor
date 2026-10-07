//
//  StreamPipelineTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Stream pipeline
/// Pins what `macmonitor` writes for a batch: one text line or one export record per event, the pipeline's own events
/// left out but still counted for drops, unreadable events counted and skipped, and JSONL escaped only for a terminal.
final class StreamPipelineTests: XCTestCase {
    private let utc = TextEventFormatter(timeZone: TimeZone(identifier: "UTC")!)
    /// A scope that suppresses nothing the fixtures hold: a process ID no event has, and no groups.
    private let nobody = PipelineScope(ancestry: [PipelineAncestor(pid: .max, groupID: 0, path: "/x/macmonitor")],
                                       includeSelf: false)
    
    /// The exit fixture as a run of events from one process, with consecutive `global_seq_num`s.
    ///
    /// - Parameters:
    ///   - globals: Their `global_seq_num`s.
    ///   - pid: The process.
    /// - Returns: The events.
    /// - Throws: The error reading the fixture.
    private func exits(_ globals: [Int], pid: Int32 = 321) throws -> [Message] {
        let exit = try XCTUnwrap(try fixtureMessages("eslogger-exit.jsonl").first)
        return globals.map { global in
            var message = exit
            message.global_seq_num = global
            message.process.pid = pid
            message.process.group_id = pid
            return message
        }
    }
    
    /// Text: one line per event, each the formatter's line for the event's header.
    ///
    /// - Throws: The error reading a fixture or encoding an event.
    func testTextIsOneLinePerEvent() throws {
        let messages = try allFixtureMessages()
        let pipeline = StreamPipeline(formatter: .text(utc), scope: nobody, forTerminal: true)
        let output = String(decoding: pipeline.process(try messages.map(wire)), as: UTF8.self)
        XCTAssertEqual(output, messages.map { utc.line(for: EventHeader($0)) }.joined())
        XCTAssertEqual(pipeline.written, messages.count)
    }
    
    /// JSONL: each event's export record, in order, byte for byte.
    ///
    /// - Throws: The error reading a fixture or encoding an event.
    func testJSONLIsTheExport() throws {
        let messages = try allFixtureMessages()
        let pipeline = StreamPipeline(formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: nobody,
                                      forTerminal: false)
        let output = String(decoding: pipeline.process(try messages.map(wire)), as: UTF8.self)
        XCTAssertEqual(output, messages.map { exportText($0) + "\n" }.joined())
    }
    
    /// Pretty prints each record like Export telemetry ▸ JSON (pretty), in order, each ending in a newline.
    ///
    /// - Throws: The error reading a fixture or encoding an event.
    func testPrettyIsThePrettyExport() throws {
        let messages = try allFixtureMessages()
        let pipeline = StreamPipeline(formatter: .jsonl([ExportEncoder(model: eventModel, pretty: true)]),
                                      scope: nobody, forTerminal: true)
        let output = String(decoding: pipeline.process(try messages.map(wire)), as: UTF8.self)
        let expected = messages.map { message in
            withStoredEvent(message) { ProcessHelpers.eventToPrettyJSON(value: $0) } + "\n"
        }
        XCTAssertEqual(output, expected.joined())
        XCTAssertGreaterThan(output.split(separator: "\n").count, messages.count, "Records span several lines")
    }
    
    /// The pipeline's own events are left out, but their sequence numbers still count: leaving them out is never a
    /// drop, and a real gap still is.
    ///
    /// - Throws: The error reading the fixture or encoding an event.
    func testOwnEventsAreLeftOutButStillCounted() throws {
        let scope = PipelineScope(ancestry: [PipelineAncestor(pid: 900, groupID: 900, path: "/x/macmonitor")],
                                  includeSelf: false)
        for format in [StreamPipeline.Formatter.text(utc), .jsonl([ExportEncoder(model: eventModel)])] {
            let pipeline = StreamPipeline(formatter: format, scope: scope, forTerminal: false)
            let batch = try (exits([1]) + exits([2, 3], pid: 900) + exits([4, 7])).map(wire)
            let lines = String(decoding: pipeline.process(batch), as: UTF8.self).split(separator: "\n")
            XCTAssertEqual(lines.count, 3)
            XCTAssertEqual(pipeline.suppressed, 2)
            XCTAssertEqual(pipeline.meter.dropped, 2, "Only 5 and 6 are missing.")
        }
    }
    
    /// An event that can't be read is counted and skipped; the rest of the batch is written.
    ///
    /// - Throws: The error reading the fixture or encoding an event.
    func testUnreadableEventsAreSkipped() throws {
        for format in [StreamPipeline.Formatter.text(utc), .jsonl([ExportEncoder(model: eventModel)])] {
            let pipeline = StreamPipeline(formatter: format, scope: nobody, forTerminal: false)
            let batch = [try wire(try exits([1])[0]), Data("{".utf8), Data(), try wire(try exits([2])[0])]
            XCTAssertEqual(String(decoding: pipeline.process(batch), as: UTF8.self).split(separator: "\n").count, 2)
            XCTAssertEqual(pipeline.unreadable, 2)
        }
    }
    
    /// JSONL for a terminal escapes C1 and bidirectional characters; piped JSONL keeps the export's bytes.
    ///
    /// - Throws: The error reading the fixture or encoding an event.
    func testJSONLIsEscapedOnlyForATerminal() throws {
        var message = try exits([1])[0]
        message.process.executable?.path = "/tmp/\u{9B}2J\u{202E}gnp.exe"
        let piped = StreamPipeline(formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: nobody,
                                   forTerminal: false).process([try wire(message)])
        XCTAssertEqual(String(decoding: piped, as: UTF8.self), exportText(message) + "\n")
        let terminal = StreamPipeline(formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: nobody,
                                      forTerminal: true).process([try wire(message)])
        XCTAssertEqual(terminal, TerminalSafeText.json(piped))
        XCTAssertNotEqual(terminal, piped)
    }
    
    /// A batch split across several encoders is written exactly as one encoder writes it, in order, and accounted for
    /// in order.
    ///
    /// - Throws: The error reading a fixture or encoding an event.
    func testParallelEncodersWriteWhatOneWrites() throws {
        let messages = try allFixtureMessages()
        let batch = try (0..<10).flatMap { _ in messages }.map(wire)
        XCTAssertGreaterThanOrEqual(batch.count, StreamPipeline.parallelThreshold)
        let one = StreamPipeline(formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: nobody,
                                 forTerminal: false)
        let four = StreamPipeline(formatter: .jsonl((0..<4).map { _ in ExportEncoder(model: eventModel) }),
                                  scope: nobody, forTerminal: false)
        XCTAssertEqual(four.process(batch), one.process(batch))
        XCTAssertEqual(four.written, batch.count)
        XCTAssertEqual(four.meter.regressions, one.meter.regressions)
        XCTAssertEqual(StreamPipeline.split(Array(batch.prefix(10)), into: 4).map(\.count), [3, 3, 3, 1])
        XCTAssertEqual(StreamPipeline.split([], into: 4).map(\.count), [0])
    }
}
