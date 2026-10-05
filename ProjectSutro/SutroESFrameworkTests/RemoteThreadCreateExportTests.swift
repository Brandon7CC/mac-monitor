//
//  RemoteThreadCreateExportTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - remote_thread_create in eslogger's format
/// Pins that exports of `remote_thread_create` events have every key eslogger writes, with eslogger's value:
/// `thread_state` as `{flavor, state: null}`, or `null` for `thread_create`. Mac Monitor adds the state's bytes
/// (`state_base64`) and the flavor's name (`thread_state_string`), and reads back what it exported before 2.2.0.
///
/// The golden records (`eslogger-remote-thread-create.jsonl`) are eslogger's output on macOS 27 (message version 10)
/// for a `thread_create_running`, scrubbed, and the same record as a synthetic `thread_create`.
final class RemoteThreadCreateExportTests: XCTestCase {
    /// eslogger's records.
    private static let esloggerFixture = "eslogger-remote-thread-create.jsonl"
    
    /// A record captured as the Security Extension captures it (see ``XCTestCase/capture(eslogger:version:fill:)``).
    ///
    /// - Parameter record: eslogger's record.
    /// - Returns: The event.
    private func capture(_ record: [String: Any]) -> Message {
        capture(eslogger: record) { $0.fillRemoteThreadCreate(eslogger: record) }
    }
    
    // MARK: eslogger parity
    
    /// Each eslogger record, opened and exported, has every value eslogger wrote, at eslogger's key path.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if its export isn't a JSON object.
    func testImportedRecordsMatchESLogger() throws {
        let records = try fixtureRecords(Self.esloggerFixture)
        XCTAssertEqual(records.count, 2)
        for (index, record) in records.enumerated() {
            let exported = try export(try importRecord(record))
            assertContains(record, exported, ignoring: Self.esloggerSequenceNumbers, "\(index)")
        }
    }
    
    /// Each eslogger record, captured from Endpoint Security's structs and exported, has every value eslogger wrote.
    ///
    /// - Throws: An `XCTest` failure if an export isn't a JSON object.
    func testCapturedRecordsMatchESLogger() throws {
        for (index, record) in try fixtureRecords(Self.esloggerFixture).enumerated() {
            assertContains(record, try export(capture(record)), ignoring: Self.esloggerSequenceNumbers, "\(index)")
        }
    }
    
    /// `thread_create_running`: eslogger's `{flavor, state: null}`, then Mac Monitor's `state_base64` (`null`, as
    /// eslogger records no bytes) and the flavor's name.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    func testThreadStateExport() throws {
        let record = try XCTUnwrap(try fixtureRecords(Self.esloggerFixture).first)
        for message in [try importRecord(record), capture(record)] {
            let event = try self.event("remote_thread_create", in: try export(message))
            let state = try XCTUnwrap(event["thread_state"] as? [String: Any])
            XCTAssertEqual(state["flavor"] as? Int, 6)
            XCTAssertTrue(state["state"] is NSNull)
            XCTAssertTrue(state["state_base64"] is NSNull)
            XCTAssertEqual(event["thread_state_string"] as? String, ThreadStateFlavor.name(of: 6))
        }
    }
    
    /// `thread_create`: `thread_state` is written as `null`, as eslogger writes it, not left out.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no such event.
    func testThreadCreateExportsNull() throws {
        let record = try fixtureRecords(Self.esloggerFixture)[1]
        for message in [try importRecord(record), capture(record)] {
            let event = try self.event("remote_thread_create", in: try export(message))
            XCTAssertTrue(event["thread_state"] is NSNull)
            XCTAssertTrue(event["thread_state_string"] is NSNull)
        }
    }
    
    /// The bytes the Security Extension records are kept in the store and exported in `state_base64`.
    ///
    /// - Throws: An `XCTest` failure if the export has no such event.
    func testCapturedBytesSurviveStore() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
        let bytes = RawMessageFixture.bytes(272)
        fixture.remoteThreadCreate(threadState: fixture.threadState(flavor: 6, bytes: bytes))
        let message = Message(from: fixture.raw)
        let event = try self.event("remote_thread_create", in: try export(message))
        let state = try XCTUnwrap(event["thread_state"] as? [String: Any])
        XCTAssertEqual(state["state_base64"] as? String, Data(bytes).base64EncodedString())
        XCTAssertTrue(state["state"] is NSNull)
        let captured = message.event.remote_thread_create?.thread_state
        withStoredEvent(message) { stored in
            XCTAssertEqual(stored.event.remote_thread_create?.thread_state, captured)
        }
    }
    
    // MARK: Mac Monitor's exports
    
    /// A Mac Monitor 2.1 export of a `remote_thread_create` event: the exit fixture with the event in its place.
    ///
    /// - Parameter threadState: The event's `thread_state`: a flavor's name, or `NSNull`.
    /// - Returns: The record.
    /// - Throws: The error reading the fixture.
    private func legacyRecord(threadState: Any) throws -> [String: Any] {
        let target = try XCTUnwrap(try fixtureObject("macmonitor-2.1-exit.jsonl")["process"])
        return try legacyRecord("remote_thread_create", type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
                                ["target": target, "thread_state": threadState])
    }
    
    /// An event exported before 2.2.0 is exported again in eslogger's shape: the name's flavor with no bytes, and the
    /// name kept in `thread_state_string`; `null` for a state it didn't name.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export has no such event.
    func testLegacyExportReexportsEsloggerShape() throws {
        let named = try event("remote_thread_create",
                              in: try export(try importRecord(try legacyRecord(threadState: "ARM_THREAD_STATE64"))))
        assertContains(["thread_state": ["flavor": 6, "state": NSNull(), "state_base64": NSNull()],
                        "thread_state_string": "ARM_THREAD_STATE64"], named, "named")
        
        let unnamed = try event("remote_thread_create",
                                in: try export(try importRecord(try legacyRecord(threadState: NSNull()))))
        assertContains(["thread_state": NSNull(), "thread_state_string": NSNull()], unnamed, "unnamed")
    }
    
    /// A 2.2.0 export reads back as it was exported, bytes and all.
    ///
    /// - Throws: The error reading a record, or an `XCTest` failure if an export isn't a JSON object.
    func testExportsRoundTrip() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
        fixture.remoteThreadCreate(threadState: fixture.threadState(flavor: 6, bytes: RawMessageFixture.bytes(272)))
        let records = try fixtureRecords(Self.esloggerFixture) + [try export(Message(from: fixture.raw))]
        for (index, record) in records.enumerated() {
            let exported = try export(try importRecord(record))
            let again = try export(try importRecord(exported))
            XCTAssertEqual(NSDictionary(dictionary: try event("remote_thread_create", in: exported)),
                           NSDictionary(dictionary: try event("remote_thread_create", in: again)), "\(index)")
        }
    }
}
