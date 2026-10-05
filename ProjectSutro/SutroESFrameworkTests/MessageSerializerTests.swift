//
//  MessageSerializerTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Message serializer
/// Pins Mac Monitor's serializer: the JSON a capture lane emits is the `Message` Mac Monitor decodes, stamped with
/// the lane's Sensor ID.
final class MessageSerializerTests: XCTestCase {
    /// An exit message is serialized as its `Message`, with the lane's Sensor ID and its sequence numbers.
    ///
    /// - Throws: The error decoding the JSON, or an `XCTest` failure if there's none.
    func testSerializesWithTheLanesSensorID() throws {
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 7, global: 42)
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR-1", encoder: StreamingJSONEncoder())
        let json = try XCTUnwrap(MessageSerializer().serialize(exit.raw, in: lane))
        let message = try JSONDecoder().decode(Message.self, from: json)
        XCTAssertEqual(message.sensor_id, "SENSOR-1")
        XCTAssertEqual(message.event_type, Int(ES_EVENT_TYPE_NOTIFY_EXIT.rawValue))
        XCTAssertEqual(message.seq_num, 7)
        XCTAssertEqual(message.global_seq_num, 42)
        XCTAssertEqual(message.process.executable?.path, "/usr/bin/true")
    }
    
    /// Events carry the macOS version the serializer read when it was made: by default, `ProcessInfo`'s version string
    /// without "Version ", which `Message` reads itself when it isn't given one.
    ///
    /// - Throws: The error decoding the JSON, or an `XCTest` failure if there's none.
    func testStampsTheMacOSVersionItWasMadeWith() throws {
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 1, global: 1)
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR-1", encoder: StreamingJSONEncoder())
        let stamped = try XCTUnwrap(MessageSerializer(macOSVersion: "27.0 (Build 26A1)").serialize(exit.raw, in: lane))
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: stamped).macOS, "27.0 (Build 26A1)")
        let expected = String(ProcessInfo.processInfo.operatingSystemVersionString.trimmingPrefix("Version "))
        let current = try XCTUnwrap(MessageSerializer().serialize(exit.raw, in: lane))
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: current).macOS, expected)
        XCTAssertEqual(Message(from: exit.raw).macOS, expected)
    }
    
    /// Through a session, the process client's exit event reaches `emit` as the `Message` Mac Monitor decodes.
    ///
    /// - Throws: ``CaptureStartError`` if the session couldn't start, or the error decoding the JSON.
    func testThroughASession() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let session = try CaptureSession(CaptureConfiguration(label: "Test"), clients: factory,
                                         serializer: MessageSerializer(), sensorID: { "SENSOR-2" },
                                         emit: emitted.append)
        session.isRecording = true
        factory.clients[0].deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 1, global: 1))
        let event = try XCTUnwrap(emitted.all.first)
        XCTAssertEqual(emitted.all.count, 1)
        XCTAssertEqual(event.eventClass, .process)
        let message = try JSONDecoder().decode(Message.self, from: event.json)
        XCTAssertEqual(message.sensor_id, "SENSOR-2")
        XCTAssertEqual(message.es_event_type, "ES_EVENT_TYPE_NOTIFY_EXIT")
    }
}
