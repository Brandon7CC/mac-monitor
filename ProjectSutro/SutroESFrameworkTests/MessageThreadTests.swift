//
//  MessageThreadTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - The message's thread
/// Pins the message's `thread`, which `ESMessage.h` declares `_Nullable` (and only there from message version 4):
/// Endpoint Security leaves it `NULL` when no thread applies, such as a trace event for `ptrace(PT_TRACE_ME)` or a
/// cs_invalidated event caused by another process's `csops(CS_OPS_MARKINVALID)`. eslogger writes `"thread": null`
/// then, so Mac Monitor captures, sends, stores and exports no thread rather than thread 0.
final class MessageThreadTests: XCTestCase {
    /// Messages whose thread is `NULL`: one of each type the SDK names, and eslogger's exit record with
    /// `"thread": null` built as Endpoint Security would deliver it.
    ///
    /// - Returns: A cs_invalidated message, a trace message whose target is set, and the exit message.
    /// - Throws: The error reading the exit fixture.
    private func messagesWithoutThread() throws -> [RawMessageFixture] {
        let invalidated = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED)
        let trace = rawMessage(type: ES_EVENT_TYPE_NOTIFY_TRACE)
        trace.message.pointee.event.trace.target = trace.process(path: "/usr/bin/lldb")
        var record = try fixtureObject("eslogger-exit.jsonl")
        record["thread"] = NSNull()
        let exit = rawMessage(type: ES_EVENT_TYPE_NOTIFY_EXIT)
        exit.fillEnvelope(eslogger: record)
        return [invalidated, trace, exit]
    }
    
    /// A `NULL` thread is captured as none and exported as `null`, as eslogger writes it.
    ///
    /// - Throws: The error reading the exit fixture, or an `XCTest` failure if an export isn't a JSON object.
    func testCapturedNullThread() throws {
        for fixture in try messagesWithoutThread() {
            let message = Message(from: fixture.raw)
            XCTAssertNil(message.thread)
            let export = try export(message)
            XCTAssertTrue(export.keys.contains("thread"))
            XCTAssertTrue(export["thread"] is NSNull, "\(message.es_event_type): \(export["thread"] ?? "missing")")
        }
    }
    
    /// A thread Endpoint Security names is exported with its ID.
    ///
    /// - Throws: An `XCTest` failure if the export isn't a JSON object.
    func testCapturedThread() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED)
        fixture.message.pointee.thread = fixture.pointer(es_thread_t(thread_id: 0x1234_5678))
        let thread = try export(Message(from: fixture.raw))["thread"] as? [String: Any]
        XCTAssertEqual(thread?["thread_id"] as? Int, 0x1234_5678)
    }
    
    /// Below message version 4 the field isn't there to read, whatever its bytes hold.
    func testThreadBeforeVersion4() {
        let fixture = rawMessage(version: 3, type: ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED)
        fixture.message.pointee.thread = fixture.pointer(es_thread_t(thread_id: 7))
        XCTAssertNil(Message(from: fixture.raw).thread)
    }
    
    /// The Security Extension's JSON reaches Mac Monitor with the thread, or without one, as captured.
    ///
    /// - Throws: The error encoding or decoding the message.
    func testWireRoundTrip() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED)
        let none = try JSONDecoder().decode(Message.self, from: try JSONEncoder().encode(Message(from: fixture.raw)))
        XCTAssertNil(none.thread)
        fixture.message.pointee.thread = fixture.pointer(es_thread_t(thread_id: 42))
        let some = try JSONDecoder().decode(Message.self, from: try JSONEncoder().encode(Message(from: fixture.raw)))
        XCTAssertEqual(some.thread?.thread_id, 42)
    }
    
    /// An eslogger record with `"thread": null` reads back as none and exports `null` again; a thread is kept.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export isn't a JSON object.
    func testImportedThread() throws {
        var record = try esloggerRecord("cs_invalidated", type: 94, [:])
        record["thread"] = NSNull()
        let none = try importRecord(record)
        XCTAssertNil(none.thread)
        XCTAssertTrue(try export(none)["thread"] is NSNull)
        let some = try importRecord(try fixtureObject("eslogger-exit.jsonl"))
        XCTAssertEqual(some.thread?.thread_id, 900_001)
        XCTAssertEqual((try export(some)["thread"] as? [String: Any])?["thread_id"] as? Int, 900_001)
    }
}
