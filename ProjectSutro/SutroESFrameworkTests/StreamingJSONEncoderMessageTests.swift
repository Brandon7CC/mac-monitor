//
//  StreamingJSONEncoderMessageTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Messages through the streaming encoder
/// Pins that every `Message` a capture lane sends is the JSON `JSONEncoder` wrote for it (byte for byte once members
/// are sorted), and that Mac Monitor decodes it back to the same message.
final class StreamingJSONEncoderMessageTests: XCTestCase {
    /// One encoder for every message, as a capture lane reuses its own.
    private let encoder = StreamingJSONEncoder()
    
    /// Encode a message with both encoders and require the same bytes in canonical form; then decode the streamed
    /// JSON as the app does and require that `JSONEncoder` writes the decoded message the same way.
    ///
    /// - Parameters:
    ///   - message: The message.
    ///   - label: Names the message in failures.
    /// - Throws: An encoder's or the decoder's error.
    private func assertSameJSON(_ message: Message, _ label: String) throws {
        let expected = try JSONCanonicalForm.canonical(try JSONEncoder().encode(message))
        let streamed = try encoder.encode(message)
        XCTAssertEqual(try JSONCanonicalForm.canonical(streamed), expected, label)
        let received = try JSONDecoder().decode(Message.self, from: streamed)
        XCTAssertEqual(try JSONCanonicalForm.canonical(try JSONEncoder().encode(received)), expected, label)
    }
    
    /// Every event of the eslogger and Mac Monitor 2.1 fixtures, read as File > Open Trace… reads them: exit, open,
    /// the Open Directory events, and remote_thread_create.
    ///
    /// - Throws: The error reading a fixture, or an encoder's or the decoder's error.
    func testImportedEventsMatchJSONEncoder() throws {
        var count = 0
        for name in ["eslogger-exit.jsonl", "eslogger-open.jsonl", "eslogger-od.jsonl",
                     "eslogger-remote-thread-create.jsonl", "macmonitor-2.1-exit.jsonl"] {
            for (line, record) in try fixtureRecords(name).enumerated() {
                guard let message = try? importRecord(record) else { continue }
                try assertSameJSON(message, "\(name) line \(line + 1)")
                count += 1
            }
        }
        XCTAssertGreaterThanOrEqual(count, 15)
    }
    
    /// Events captured from raw messages as the Security Extension captures them: Open Directory events, a
    /// remote_thread_create, and events whose unions name an arm Mac Monitor doesn't know.
    ///
    /// - Throws: The error reading a fixture, or an encoder's or the decoder's error.
    func testCapturedEventsMatchJSONEncoder() throws {
        for record in try fixtureRecords("eslogger-od.jsonl") {
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
            fixture.fillEnvelope(eslogger: record)
            guard fixture.fillODEvent(eslogger: record) else { continue }
            try assertSameJSON(Message(from: fixture.raw), "od \(record["event_type"] ?? "")")
        }
        for record in try fixtureRecords("eslogger-remote-thread-create.jsonl") {
            try assertSameJSON(capture(eslogger: record) { $0.fillRemoteThreadCreate(eslogger: record) }, "rtc")
        }
        
        let exit = sequencedMessage(ES_EVENT_TYPE_NOTIFY_EXIT, seq: 3, global: 9)
        try assertSameJSON(Message(from: exit.raw, sensorID: "SENSOR-1", macOS: "27.0"), "exit")
        
        let create = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        create.message.pointee.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH
        create.message.pointee.event.create.destination.new_path.dir = create.file("/private/tmp/example")
        create.message.pointee.event.create.destination.new_path.filename = create.token("Quarterly \"Report\".txt")
        try assertSameJSON(Message(from: create.raw), "create")
        
        let unknownCreate = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CREATE)
        unknownCreate.message.pointee.event.create.destination_type = es_destination_type_t(rawValue: 9)
        try assertSameJSON(Message(from: unknownCreate.raw), "create with an unknown destination")
        
        let gatekeeper = rawMessage(type: ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE)
        let override = gatekeeper.allocate(es_event_gatekeeper_user_override_t.self)
        override.pointee.file_type = es_gatekeeper_user_override_file_type_t(rawValue: 7)
        gatekeeper.message.pointee.event.gatekeeper_user_override = override
        try assertSameJSON(Message(from: gatekeeper.raw), "gatekeeper_user_override with an unknown file type")
        
        let login = rawMessage(type: ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN)
        var event = es_event_login_login_t()
        event.success = false
        event.failure_message = login.token("Bad\tpassword\n")
        event.username = login.token("root")
        login.message.pointee.event.login_login = login.pointer(event)
        try assertSameJSON(Message(from: login.raw), "login_login")
    }
}
