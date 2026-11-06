//
//  StreamingJSONEncoderPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Encoding messages
/// Times encoding a built `Message` with a lane's `StreamingJSONEncoder`, the second half of a capture lane's
/// per-event cost (the first is ``MessageBuildPerformanceTests``'s), and with `JSONEncoder`, which it replaced, for
/// scale: `capture.encode.jsonencoder.*`.
final class StreamingJSONEncoderPerformanceTests: PerformanceTestCase {
    /// Messages per sample.
    private static let events = 2_000
    
    /// Encode a message with a lane's encoder, reused for every event as a lane reuses its own.
    ///
    /// - Parameters:
    ///   - name: The event's name in the benchmark's.
    ///   - message: The message.
    /// - Throws: The encoder's error, or the error writing the results.
    private func benchmarkEncoding(_ name: String, _ message: Message) throws {
        let encoder = StreamingJSONEncoder()
        try benchmark("capture.encode.\(name)", operations: Self.events) {
            for _ in 0..<Self.events { _ = try encoder.encode(message) }
        }
    }
    
    /// Encode a message with a `JSONEncoder` made once.
    ///
    /// - Parameters:
    ///   - name: The event's name in the benchmark's.
    ///   - message: The message.
    /// - Throws: The encoder's error, or the error writing the results.
    private func benchmarkFoundationEncoding(_ name: String, _ message: Message) throws {
        let encoder = JSONEncoder()
        try benchmark("capture.encode.jsonencoder.\(name)", operations: Self.events) {
            for _ in 0..<Self.events { _ = try encoder.encode(message) }
        }
    }
    
    /// A capture benchmark's message, built.
    ///
    /// - Parameter event: The event.
    /// - Returns: The message.
    /// - Throws: The error writing the files it names.
    private func built(_ event: CaptureBenchmarkEvent) throws -> Message {
        Message(from: try rawMessage(for: event).raw, sensorID: "SENSOR")
    }
    
    func testExec() throws { try benchmarkEncoding("exec", try benchmarkExec()) }
    func testOpen() throws { try benchmarkEncoding("open", try built(.open)) }
    func testClose() throws { try benchmarkEncoding("close", try built(.close)) }
    func testCreate() throws { try benchmarkEncoding("create", try built(.create)) }
    func testMmap() throws { try benchmarkEncoding("mmap", try built(.mmap)) }
    func testFork() throws { try benchmarkEncoding("fork", try built(.fork)) }
    func testExecWithJSONEncoder() throws { try benchmarkFoundationEncoding("exec", try benchmarkExec()) }
    func testOpenWithJSONEncoder() throws { try benchmarkFoundationEncoding("open", try built(.open)) }
}
