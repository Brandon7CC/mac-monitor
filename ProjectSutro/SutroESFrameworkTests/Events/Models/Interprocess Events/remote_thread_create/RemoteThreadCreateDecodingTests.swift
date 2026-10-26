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
/// Extension (`JSONDecoder`) and by File > Open Trace… (``TraceDecoder``): eslogger's object or `null`, a 3.0.0 export,
/// and the flavor's name (or nothing) that Mac Monitor wrote before 3.0.0.
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
    
    /// The thread state of a 3.0.0 export with bytes.
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
        object["target"] = try jsonObject(encoding: target())
        switch reader {
        case .wire:
            let data = try JSONSerialization.data(withJSONObject: object)
            return try JSONDecoder().decode(RemoteThreadCreateEvent.self, from: data)
        case .export, .eslogger:
            return try TraceDecoder(object as NSDictionary, enriching: reader == .eslogger)
                .decode(RemoteThreadCreateEvent.self)
        }
    }
    
    // MARK: Every form of thread_state
    
    /// Each form of an event's keys besides its target, the readers that see it, and the thread state and flavor name
    /// they read, with what the case pins. ``Reader/eslogger`` derives its own name, from the flavor.
    private static let forms: [(label: String, thread: [String: Any], readers: [Reader], state: ThreadState?,
                                name: String?)] = [
        ("eslogger's thread state: its flavor, no bytes, and the flavor's name when it's derived",
         ["thread_state": ["flavor": 6, "state": NSNull()]], Reader.allCases, ThreadState(flavor: 6, state_base64: nil),
         nil),
        ("eslogger's null for thread_create", ["thread_state": NSNull()], Reader.allCases, nil, nil),
        ("A flavor neither architecture names is kept, without a name (TraceDecoder made it null before 3.0.0)",
         ["thread_state": ["flavor": 999, "state": NSNull()]], Reader.allCases,
         ThreadState(flavor: 999, state_base64: nil), nil),
        ("Should eslogger ever write state's bytes, as it writes an es_token_t, they're read",
         ["thread_state": ["flavor": 6, "state": "AAEC/w=="]], Reader.allCases, exported, nil),
        ("A 3.0.0 export or message reads back exactly: its bytes and its flavor's name",
         ["thread_state": ["flavor": 6, "state": NSNull(), "state_base64": "AAEC/w=="],
          "thread_state_string": "ARM_THREAD_STATE64"], [.wire, .export], exported, "ARM_THREAD_STATE64"),
        ("The ARM name Mac Monitor wrote before 3.0.0 is read as its flavor, without bytes",
         ["thread_state": "ARM_THREAD_STATE64"], [.wire, .export], ThreadState(flavor: 6, state_base64: nil),
         "ARM_THREAD_STATE64"),
        ("The x86 name Mac Monitor wrote before 3.0.0 is read as its flavor, without bytes",
         ["thread_state": "x86_THREAD_STATE64"], [.wire, .export], ThreadState(flavor: 4, state_base64: nil),
         "x86_THREAD_STATE64"),
        ("A name before 3.0.0 that's no flavor's is kept as the name", ["thread_state": "BOGUS"], [.wire, .export],
         nil, "BOGUS"),
        ("Before 3.0.0 an unnamed flavor was written as null", ["thread_state": NSNull()], [.wire, .export], nil, nil),
        ("Before 3.0.0 an unnamed flavor was left out", [:], Reader.allCases, nil, nil),
    ]
    
    /// Each form of ``forms`` reads as its thread state and flavor name, by each of its readers.
    func testForms() {
        for (label, thread, readers, state, name) in Self.forms {
            for reader in readers {
                let message = "\(label) (\(reader.rawValue))"
                do {
                    let event = try decode(thread, with: reader)
                    XCTAssertEqual(event.thread_state, state, message)
                    let expected = reader == .eslogger ? state.flatMap { ThreadStateFlavor.name(of: $0.flavor) } : name
                    XCTAssertEqual(event.thread_state_string, expected, message)
                    XCTAssertEqual(event.target.executable?.path, "/bin/sleep", message)
                } catch {
                    XCTFail("\(message): \(error)")
                }
            }
        }
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
    
    // MARK: The Security Extension's messages
    
    /// The Security Extension records the thread state and the flavor's name, and the app reads them back over XPC;
    /// a `thread_create` sends neither key.
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
        let sent = try jsonObject(data)
        XCTAssertNil(sent["thread_state"])
        XCTAssertNil(sent["thread_state_string"])
        let decoded = try JSONDecoder().decode(RemoteThreadCreateEvent.self, from: data)
        XCTAssertEqual(decoded, created)
        XCTAssertNil(decoded.thread_state)
    }
    
    /// A whole `Message` from Endpoint Security goes over XPC with its thread state, and one from an older Security
    /// Extension, which sent the flavor's name, still decodes.
    func testMessages() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
        fixture.remoteThreadCreate(threadState: fixture.threadState(bytes: [0, 1, 2, 0xFF]))
        let sent = try JSONEncoder().encode(Message(from: fixture.raw))
        let received = try JSONDecoder().decode(Message.self, from: sent)
        XCTAssertEqual(received.event.remote_thread_create?.thread_state, Self.exported)
        
        var message = try jsonObject(sent)
        message[path: "event", "remote_thread_create", "_0", "thread_state"] = "ARM_THREAD_STATE64"
        message[path: "event", "remote_thread_create", "_0", "thread_state_string"] = nil
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
