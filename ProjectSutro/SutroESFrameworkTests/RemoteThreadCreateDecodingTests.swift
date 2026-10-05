//
//  RemoteThreadCreateDecodingTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Reading remote_thread_create events
/// Pins that every form of a `remote_thread_create` event's `thread_state` is read, by the app from the Security
/// Extension (`JSONDecoder`) and by File > Open Trace… (``TraceDecoder``): eslogger's object or `null`, a 2.2.0 export,
/// and the flavor's name (or nothing) that Mac Monitor wrote before 2.2.0.
final class RemoteThreadCreateDecodingTests: XCTestCase {
    /// How an event is read.
    private enum Reader: String, CaseIterable {
        /// The app, reading the Security Extension's messages.
        case wire
        /// File > Open Trace…, reading a Mac Monitor export.
        case export
        /// File > Open Trace…, reading eslogger's JSON: Mac Monitor's fields are derived.
        case eslogger
    }
    
    /// The thread state of a 2.2.0 export with bytes.
    private static let exported = ThreadState(flavor: 6, state_base64: "AAEC/w==")
    
    /// A process to create threads in, as the Security Extension sends one: `/bin/sleep`.
    ///
    /// - Returns: The process.
    private func target() -> SutroESFramework.Process {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
        let process = fixture.process(path: "/bin/sleep", signingID: "com.apple.sleep", pid: 4243)
        return SutroESFramework.Process(from: process.pointee, version: 10)
    }
    
    /// Read an event.
    ///
    /// - Parameters:
    ///   - thread: The event's `thread_state` and other keys, beside the ``target()``.
    ///   - reader: How it's read.
    /// - Returns: The event.
    /// - Throws: The error decoding it.
    private func decode(_ thread: [String: Any], with reader: Reader) throws -> RemoteThreadCreateEvent {
        var object = thread
        object["target"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(target()))
        switch reader {
        case .wire:
            let data = try JSONSerialization.data(withJSONObject: object)
            return try JSONDecoder().decode(RemoteThreadCreateEvent.self, from: data)
        case .export, .eslogger:
            return try TraceDecoder(object as NSDictionary, enriching: reader == .eslogger)
                .decode(RemoteThreadCreateEvent.self)
        }
    }
    
    /// Assert how each reader reads an event.
    ///
    /// - Parameters:
    ///   - thread: The event's keys besides its target.
    ///   - readers: The readers that check it.
    ///   - state: The thread state expected.
    ///   - name: The flavor name expected from a reader other than ``Reader/eslogger``, which derives its own.
    ///   - line: The caller's line.
    private func assertReads(_ thread: [String: Any], by readers: [Reader] = Reader.allCases, as state: ThreadState?,
                             name: String?, line: UInt = #line) {
        for reader in readers {
            do {
                let event = try decode(thread, with: reader)
                XCTAssertEqual(event.thread_state, state, reader.rawValue, line: line)
                let expected = reader == .eslogger ? state.flatMap { ThreadStateFlavor.name(of: $0.flavor) } : name
                XCTAssertEqual(event.thread_state_string, expected, reader.rawValue, line: line)
                XCTAssertEqual(event.target.executable?.path, "/bin/sleep", reader.rawValue, line: line)
            } catch {
                XCTFail("\(reader.rawValue): \(error)", line: line)
            }
        }
    }
    
    // MARK: eslogger
    
    /// eslogger's thread state: its flavor, no bytes, and the flavor's name when it's derived.
    func testESLoggerThreadState() {
        assertReads(["thread_state": ["flavor": 6, "state": NSNull()]], as: ThreadState(flavor: 6, state_base64: nil),
                    name: nil)
    }
    
    /// eslogger's `null` for `thread_create`.
    func testESLoggerNullThreadState() {
        assertReads(["thread_state": NSNull()], as: nil, name: nil)
    }
    
    /// A flavor neither architecture names is kept, without a name. TraceDecoder bridged `thread_state` to its name
    /// before 2.2.0, which made such a state `null`.
    func testUnnamedFlavorIsKept() {
        assertReads(["thread_state": ["flavor": 999, "state": NSNull()]],
                    as: ThreadState(flavor: 999, state_base64: nil), name: nil)
    }
    
    /// Should eslogger ever write `state`'s bytes, as eslogger writes an `es_token_t`, they're read.
    func testESLoggerStateBytes() {
        assertReads(["thread_state": ["flavor": 6, "state": "AAEC/w=="]], as: Self.exported, name: nil)
    }
    
    /// A `flavor` that isn't a number is an error, so the event is skipped and counted rather than read wrong.
    func testNonNumericFlavorThrows() {
        for reader in Reader.allCases {
            let thread = ["thread_state": ["flavor": "x"]]
            XCTAssertThrowsError(try decode(thread, with: reader), reader.rawValue) { error in
                guard case DecodingError.typeMismatch = error else {
                    return XCTFail("\(reader.rawValue): expected a type mismatch, found \(error)")
                }
            }
        }
    }
    
    // MARK: Mac Monitor
    
    /// A 2.2.0 export or message reads back exactly: its bytes and its flavor's name.
    func testExportRoundTrips() {
        let thread: [String: Any] = [
            "thread_state": ["flavor": 6, "state": NSNull(), "state_base64": "AAEC/w=="],
            "thread_state_string": "ARM_THREAD_STATE64",
        ]
        assertReads(thread, by: [.wire, .export], as: Self.exported, name: "ARM_THREAD_STATE64")
    }
    
    /// The name Mac Monitor wrote before 2.2.0 is read as its flavor, without bytes, on either architecture.
    func testLegacyNames() {
        let legacy = [Reader.wire, .export]
        assertReads(["thread_state": "ARM_THREAD_STATE64"], by: legacy, as: ThreadState(flavor: 6, state_base64: nil),
                    name: "ARM_THREAD_STATE64")
        assertReads(["thread_state": "x86_THREAD_STATE64"], by: legacy, as: ThreadState(flavor: 4, state_base64: nil),
                    name: "x86_THREAD_STATE64")
        assertReads(["thread_state": "BOGUS"], by: legacy, as: nil, name: "BOGUS")
    }
    
    /// Before 2.2.0 an unnamed flavor was written as `null`, or left out.
    func testLegacyMissingThreadState() {
        assertReads(["thread_state": NSNull()], by: [.wire, .export], as: nil, name: nil)
        assertReads([:], as: nil, name: nil)
    }
    
    // MARK: The Security Extension's messages
    
    /// The Security Extension records the thread state and the flavor's name, and the app reads them back over XPC;
    /// a `thread_create` sends neither key.
    ///
    /// - Throws: The error encoding or decoding an event.
    func testWireRoundTrip() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
        let threadState = fixture.threadState(bytes: [0, 1, 2, 0xFF])
        let running = RemoteThreadCreateEvent(target: target(), threadState: threadState)
        let received = try JSONDecoder().decode(RemoteThreadCreateEvent.self, from: JSONEncoder().encode(running))
        XCTAssertEqual(received, running)
        XCTAssertEqual(received.id, running.id)
        XCTAssertEqual(received.thread_state, Self.exported)
        XCTAssertEqual(received.thread_state_string, ThreadStateFlavor.name(of: 6))
        
        let created = RemoteThreadCreateEvent(target: target(), threadState: nil)
        let data = try JSONEncoder().encode(created)
        let sent = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertNil(sent["thread_state"])
        XCTAssertNil(sent["thread_state_string"])
        XCTAssertEqual(try JSONDecoder().decode(RemoteThreadCreateEvent.self, from: data), created)
    }
    
    /// A whole `Message` from Endpoint Security goes over XPC with its thread state, and one from an older Security
    /// Extension, which sent the flavor's name, still decodes.
    ///
    /// - Throws: The error encoding or decoding a message.
    func testMessages() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
        fixture.remoteThreadCreate(threadState: fixture.threadState(bytes: [0, 1, 2, 0xFF]))
        let sent = try JSONEncoder().encode(Message(from: fixture.raw))
        let received = try JSONDecoder().decode(Message.self, from: sent)
        XCTAssertEqual(received.event.remote_thread_create?.thread_state, Self.exported)
        
        var message = try XCTUnwrap(try JSONSerialization.jsonObject(with: sent) as? [String: Any])
        let event = try XCTUnwrap((message["event"] as? [String: Any])?["remote_thread_create"] as? [String: Any])
        var legacy = try XCTUnwrap(event["_0"] as? [String: Any])
        legacy["thread_state"] = "ARM_THREAD_STATE64"
        legacy["thread_state_string"] = nil
        message["event"] = ["remote_thread_create": ["_0": legacy]]
        let old = try JSONDecoder().decode(Message.self, from: JSONSerialization.data(withJSONObject: message))
        XCTAssertEqual(old.event.remote_thread_create?.thread_state, ThreadState(flavor: 6, state_base64: nil))
        XCTAssertEqual(old.event.remote_thread_create?.thread_state_string, "ARM_THREAD_STATE64")
    }
    
    /// Recording from Endpoint Security's structs: a `NULL` `thread_state` is none, and a state keeps its bytes and
    /// derives its flavor's name.
    func testCapture() {
        let created = rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
        created.remoteThreadCreate(threadState: nil)
        let none = RemoteThreadCreateEvent(from: created.raw)
        XCTAssertNil(none.thread_state)
        XCTAssertNil(none.thread_state_string)
        XCTAssertEqual(none.target.executable?.path, "/bin/sleep")
        
        let running = rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
        running.remoteThreadCreate(threadState: running.threadState(flavor: 6, bytes: [0, 1, 2, 0xFF]))
        let event = RemoteThreadCreateEvent(from: running.raw)
        XCTAssertEqual(event.thread_state, Self.exported)
        XCTAssertEqual(event.thread_state_string, ThreadStateFlavor.name(of: 6))
    }
    
    /// The event tables show the flavor's name, or its number when it has none, before the target's path.
    func testSummary() {
        let named = RemoteThreadCreateEvent(target: target(), threadState: es_thread_state_t(
            flavor: 6, state: es_token_t(size: 0, data: nil)))
        let unnamed = RemoteThreadCreateEvent(target: target(), threadState: es_thread_state_t(
            flavor: 999, state: es_token_t(size: 0, data: nil)))
        let none = RemoteThreadCreateEvent(target: target(), threadState: nil)
        let context = { (event: RemoteThreadCreateEvent) in
            EventType.remote_thread_create(event).summary(initiatingPath: "/usr/local/bin/injector").context
        }
        XCTAssertEqual(context(named), "[\(ThreadStateFlavor.name(of: 6) ?? "?")] /bin/sleep")
        XCTAssertEqual(context(unnamed), "[flavor 999] /bin/sleep")
        XCTAssertEqual(context(none), "/bin/sleep")
    }
}
