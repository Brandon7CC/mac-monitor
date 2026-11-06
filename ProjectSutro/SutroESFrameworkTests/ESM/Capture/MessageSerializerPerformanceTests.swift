//
//  MessageSerializerPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Serializing on a capture lane
/// Times what a capture lane pays per event on its handler queue, where every microsecond counts towards Endpoint
/// Security's drops: `MessageSerializer.serializeEvent`, which builds the `Message` (with its enrichment), stamps the
/// launched-by parent and encodes it with the lane's streaming encoder.
///
/// Each sample serializes the same message 2,000 times on one lane, so the lane's caches are warm, as they are for a
/// busy client. `capture.build.*` (``MessageBuildPerformanceTests``) and `capture.encode.*`
/// (``StreamingJSONEncoderPerformanceTests``) split the cost.
final class MessageSerializerPerformanceTests: PerformanceTestCase {
    /// Messages per sample.
    private static let events = 2_000

    /// Serialize an event's message on a lane of its client's class.
    ///
    /// - Parameter event: The event.
    /// - Throws: ``BenchmarkFailure`` if a message isn't encoded, or the error writing the results.
    private func benchmarkSerializing(_ event: CaptureBenchmarkEvent) throws {
        let fixture = try rawMessage(for: event)
        let serializer = MessageSerializer(processPath: { _, _ in "/bin/zsh" })
        let lane = LaneContext(eventClass: event.eventClass, sensorID: "SENSOR", encoder: StreamingJSONEncoder())
        try benchmark("capture.serialize.\(event.rawValue)", operations: Self.events) {
            for _ in 0..<Self.events {
                guard case .json = serializer.serializeEvent(fixture.raw, in: lane) else {
                    throw BenchmarkFailure("\(event) wasn't encoded")
                }
            }
        }
    }

    func testOpen() throws { try benchmarkSerializing(.open) }
    func testOpenByThirdParty() throws { try benchmarkSerializing(.openByThirdParty) }
    func testClose() throws { try benchmarkSerializing(.close) }
    func testCreate() throws { try benchmarkSerializing(.create) }
    func testMmap() throws { try benchmarkSerializing(.mmap) }
    func testFork() throws { try benchmarkSerializing(.fork) }
    func testExit() throws { try benchmarkSerializing(.exit) }
}
