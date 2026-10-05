//
//  XCTestCase+Capture.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
import os
@testable import SutroESFramework


// MARK: - Stub serializer
/// A serializer a test controls, so most capture tests never build a `Message`.
struct StubSerializer: EventSerializing {
    /// Serializes each message.
    let body: (UnsafePointer<es_message_t>, LaneContext) -> Data?
    
    /// Writes each message's `global_seq_num` as its JSON, so a test can follow the order events leave a lane.
    static let globalSequence = StubSerializer { message, _ in Data("\(message.pointee.global_seq_num)".utf8) }
    
    /// Run ``body``.
    ///
    /// - Parameters:
    ///   - message: The message.
    ///   - lane: The lane's context.
    /// - Returns: What ``body`` returns.
    func serialize(_ message: UnsafePointer<es_message_t>, in lane: LaneContext) -> Data? {
        body(message, lane)
    }
}


// MARK: - Emitted events
/// Collects what a capture session emits, from any thread.
final class EmittedEvents {
    private let lock = OSAllocatedUnfairLock<[CapturedEvent]>(uncheckedState: [])
    
    /// Every event, in the order they were emitted.
    var all: [CapturedEvent] {
        lock.withLockUnchecked { $0 }
    }
    
    /// Collect one event.
    ///
    /// - Parameter event: The event.
    func append(_ event: CapturedEvent) {
        lock.withLockUnchecked { $0.append(event) }
    }
    
    /// What one class emitted, as ``StubSerializer/globalSequence`` writes it.
    ///
    /// - Parameter eventClass: The class.
    /// - Returns: Its events' `global_seq_num`s, in order.
    func globalSequences(of eventClass: EventClass) -> [UInt64] {
        all.filter { $0.eventClass == eventClass }.compactMap { UInt64(String(decoding: $0.json, as: UTF8.self)) }
    }
}


// MARK: - Sessions on fakes
extension XCTestCase {
    /// A capture session on fake clients, with Sensor ID "SENSOR" unless a test supplies its own.
    ///
    /// - Parameters:
    ///   - configuration: The events and mutes.
    ///   - factory: Makes the fake clients.
    ///   - serializer: Builds each event's JSON.
    ///   - sensorID: Computes the Sensor ID.
    ///   - emitted: Collects what the session emits.
    /// - Returns: The session.
    /// - Throws: ``CaptureStartError`` if the session couldn't start.
    func makeSession(_ configuration: CaptureConfiguration = CaptureConfiguration(label: "Test"),
                     factory: FakeEndpointSecurityClientFactory,
                     serializer: StubSerializer = .globalSequence,
                     sensorID: @escaping () -> String = { "SENSOR" },
                     emitted: EmittedEvents = EmittedEvents()) throws -> CaptureSession {
        try CaptureSession(configuration, clients: factory, serializer: serializer, sensorID: sensorID,
                           emit: emitted.append)
    }
    
    /// A raw message with sequence numbers, which stays alive until the test ends.
    ///
    /// - Parameters:
    ///   - type: The event's type.
    ///   - seq: Its `seq_num`, per client and event type.
    ///   - global: Its `global_seq_num`, per client.
    ///   - version: The message's version.
    /// - Returns: The message's fixture.
    func sequencedMessage(_ type: es_event_type_t, seq: UInt64 = 0, global: UInt64,
                          version: UInt32 = 10) -> RawMessageFixture {
        let fixture = rawMessage(version: version, type: type)
        fixture.message.pointee.seq_num = seq
        fixture.message.pointee.global_seq_num = global
        return fixture
    }
    
    /// Wait for a condition another thread makes true.
    ///
    /// - Parameters:
    ///   - timeout: How long to wait, in seconds.
    ///   - condition: Checked every millisecond.
    /// - Returns: `true` once the condition holds, `false` if it still doesn't after `timeout`.
    func waitUntil(timeout: TimeInterval = 5, _ condition: () -> Bool) -> Bool {
        let deadline = Date(timeIntervalSinceNow: timeout)
        while !condition() {
            guard Date() < deadline else { return false }
            usleep(1_000)
        }
        return true
    }
}
