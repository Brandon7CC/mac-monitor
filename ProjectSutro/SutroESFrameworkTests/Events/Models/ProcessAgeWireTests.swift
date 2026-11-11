//
//  ProcessAgeWireTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Process ages from a 3.0.0 Security Extension
/// Pins that events from a 3.0.0 Security Extension, which sends no process ages, get them where they're received: in
/// the app (``Message/completeReceived(path:)``, which `EndpointSecurityManager.receive` calls) and in `macmonitor`
/// (``StreamPipeline``).
final class ProcessAgeWireTests: XCTestCase {
    /// The initiating shell's age at the fork, 2026-10-04T00:01:55.281215406Z: it started at 00:00:01.000001Z.
    private static let shellAge = 114_281
    /// The fork's child's age: it started 5 s before the fork.
    private static let childAge = 5_000

    /// A shell's fork, with both processes' ages.
    ///
    /// - Returns: The fork.
    /// - Throws: The error reading the fixture.
    private func fork() throws -> Message {
        var child = try esloggerProcess(pid: 402, pidversion: 4020, path: "/bin/zsh", parent: (401, 4010))
        child["start_time"] = "2026-10-04T00:01:50.281215Z"
        let fork = try forkMessage(by: try shell(), of: child)
        XCTAssertEqual(fork.process.process_age_ms, Self.shellAge)
        XCTAssertEqual(fork.event.fork?.child.process_age_ms, Self.childAge)
        return fork
    }

    /// What a 3.0.0 Security Extension sends for an event: its wire JSON without any `process_age_ms`.
    ///
    /// - Parameter message: The event.
    /// - Returns: The JSON.
    /// - Throws: An `XCTest` failure if the wire JSON lacks an age to remove, or the error encoding it.
    private func withoutAges(_ message: Message) throws -> Data {
        var object = try jsonObject(try wire(message))
        for path: [JSONStep] in [["process"], ["event", "fork", "_0", "child"]] {
            XCTAssertNotNil(object[path: path + ["process_age_ms"]], "\(path)")
            object[path: path + ["process_age_ms"]] = nil
        }
        return try JSONSerialization.data(withJSONObject: object)
    }

    /// The app decodes the event and derives both processes' ages.
    func testTheAppDerivesAges() throws {
        var received = try JSONDecoder().decode(Message.self, from: try withoutAges(try fork()))
        XCTAssertNil(received.process.process_age_ms)
        received.completeReceived { _, _ in nil }
        XCTAssertEqual(received.process.process_age_ms, Self.shellAge)
        XCTAssertEqual(received.event.fork?.child.process_age_ms, Self.childAge)
    }

    /// `macmonitor` writes the record it would write for the event with its ages.
    func testMacmonitorDerivesAges() throws {
        let fork = try fork()
        /// A scope that suppresses nothing the fork holds.
        let nobody = PipelineScope(ancestry: [PipelineAncestor(pid: .max, groupID: 0, path: "/x/macmonitor")],
                                   includeSelf: false)
        let pipeline = StreamPipeline(formatter: .jsonl([ExportEncoder(model: eventModel)]), scope: nobody,
                                      forTerminal: false)
        let output = String(decoding: pipeline.process([try withoutAges(fork)]), as: UTF8.self)
        XCTAssertEqual(output, exportText(fork) + "\n")
        let record = try jsonObject(Data(output.utf8))
        XCTAssertEqual(record[path: "process", "process_age_ms"] as? Int, Self.shellAge)
        XCTAssertEqual(record[path: "event", "fork", "child", "process_age_ms"] as? Int, Self.childAge)
    }
}
