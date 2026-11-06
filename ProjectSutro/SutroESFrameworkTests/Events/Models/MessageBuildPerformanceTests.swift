//
//  MessageBuildPerformanceTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 11/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Building messages
/// Times building a `Message` from a raw message, the first half of a capture lane's per-event cost: reading
/// Endpoint Security's structs, and Mac Monitor's enrichment of them (File Quarantine, code signing types, user
/// names). The other half is ``StreamingJSONEncoderPerformanceTests``'s.
final class MessageBuildPerformanceTests: PerformanceTestCase {
    /// Messages per sample.
    private static let events = 2_000
    
    /// Build an event's message, with the macOS version and SIP status the serializer stamps.
    ///
    /// - Parameter event: The event.
    /// - Throws: The error writing the files it names, or the results.
    private func benchmarkBuilding(_ event: CaptureBenchmarkEvent) throws {
        let fixture = try rawMessage(for: event)
        let (macOS, sip) = (Message.currentMacOSVersion(), SIPStatus.current)
        try benchmark("capture.build.\(event.rawValue)", operations: Self.events) {
            for _ in 0..<Self.events {
                _ = Message(from: fixture.raw, sensorID: "SENSOR", macOS: macOS, sipStatus: sip)
            }
        }
    }
    
    func testOpen() throws { try benchmarkBuilding(.open) }
    func testOpenByThirdParty() throws { try benchmarkBuilding(.openByThirdParty) }
    func testClose() throws { try benchmarkBuilding(.close) }
    func testCreate() throws { try benchmarkBuilding(.create) }
    func testMmap() throws { try benchmarkBuilding(.mmap) }
    func testFork() throws { try benchmarkBuilding(.fork) }
    func testExit() throws { try benchmarkBuilding(.exit) }
}
