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

    /// Events carry the boot session's identifier as the serializer read it: the kernel's UUID for this start of
    /// the Mac, which a process key is only unique within. A trace without it reads as none.
    func testStampsTheBootSession() throws {
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 1, global: 1)
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR-1", encoder: StreamingJSONEncoder())
        let boot = "0F1E2D3C-4B5A-4978-8695-A4B3C2D1E0F9"
        let stamped = try XCTUnwrap(MessageSerializer(bootSession: boot).serialize(exit.raw, in: lane))
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: stamped).boot_session_uuid, boot)
        let current = try XCTUnwrap(BootSession.current)
        XCTAssertNotNil(UUID(uuidString: current))
        XCTAssertEqual(current, current.uppercased(), "As the schema's UUIDs are written")
        XCTAssertEqual(Message(from: exit.raw).boot_session_uuid, current)
        let exported = try export(Message(from: exit.raw, bootSession: boot))
        XCTAssertEqual(exported["boot_session_uuid"] as? String, boot)
        XCTAssertEqual(try importRecord(exported).boot_session_uuid, boot)
        XCTAssertTrue(try export(Message(from: exit.raw, bootSession: nil))["boot_session_uuid"] is NSNull)
    }

    /// Events carry System Integrity Protection's status as the serializer read it, as `csrutil status` names it:
    /// enabled with nothing allowed, disabled with everything `csrutil disable` allows, custom with less.
    func testStampsTheSIPStatus() throws {
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 1, global: 1)
        let lane = LaneContext(eventClass: .process, sensorID: "SENSOR-1", encoder: StreamingJSONEncoder())
        let stamped = try XCTUnwrap(MessageSerializer(sipStatus: .disabled).serialize(exit.raw, in: lane))
        XCTAssertEqual(try JSONDecoder().decode(Message.self, from: stamped).sip_status, "disabled")
        XCTAssertEqual(Message(from: exit.raw).sip_status, SIPStatus.current?.rawValue)
        XCTAssertNotNil(SIPStatus.current)
        XCTAssertEqual(SIPStatus(configuration: 0), .enabled)
        XCTAssertEqual(SIPStatus(configuration: 0x6f), .disabled, "csrutil disable")
        XCTAssertEqual(SIPStatus(configuration: 0x7f), .disabled, "csrutil disable with Apple internal")
        XCTAssertEqual(SIPStatus(configuration: 0x2), .custom, "csrutil enable --without fs")
        XCTAssertEqual(SIPStatus(configuration: 0x6e), .custom)
    }
    
    /// A lane that holds app execs leaves its events' sequence steps for the hold, which advances them as it sends
    /// each event, in the lane's order. Another lane advances them as it builds the event.
    func testALaneThatHoldsDefersSequenceSteps() throws {
        let exited = IndicatorSequence.Step(name: "exit", predicate: "event.exit != nil")
        let never = IndicatorSequence.Step(name: "never",
                                           predicate: "event.exit != nil AND process.audit_token.pid < 0")
        let sequence = sequenceIndicator(IndicatorSequence(order: .ordered, within: 5, by: ["process.audit_token.pid"],
                                                           steps: [exited, never]))
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 1, global: 1)
        for holds in [true, false] {
            let indicators = CompiledIndicators([sequence])
            let lane = LaneContext(eventClass: .process, sensorID: "SENSOR-1", encoder: StreamingJSONEncoder(),
                                   holdsEvents: holds, indicators: indicators)
            switch try XCTUnwrap(MessageSerializer().serializeEvent(exit.raw, in: lane)) {
            case .stamped(_, let steps):
                XCTAssertTrue(holds)
                XCTAssertEqual(steps.count, 1)
            case .json:
                XCTAssertFalse(holds)
            case .held:
                XCTFail("Not an app's exec, nor a written file")
            }
            XCTAssertEqual(indicators.openChains, holds ? 0 : 1, "Holds: \(holds)")
        }
    }

    /// Through a session, the process client's exit event reaches `emit` as the `Message` Mac Monitor decodes.
    func testThroughASession() throws {
        let factory = FakeEndpointSecurityClientFactory()
        let emitted = EmittedEvents()
        let session = try CaptureSession(CaptureConfiguration(label: "Test"), clients: factory,
                                         serializer: MessageSerializer(), sensorID: { "SENSOR-2" },
                                         emit: emitted.append)
        session.isRecording = true
        factory.client(.process).deliver(sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 1, global: 1))
        let event = try XCTUnwrap(emitted.all.first)
        XCTAssertEqual(emitted.all.count, 1)
        XCTAssertEqual(event.eventClass, .process)
        let message = try JSONDecoder().decode(Message.self, from: event.json)
        XCTAssertEqual(message.sensor_id, "SENSOR-2")
        XCTAssertEqual(message.es_event_type, "ES_EVENT_TYPE_NOTIFY_EXIT")
    }
}
