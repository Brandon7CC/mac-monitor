//
//  ThreadStateTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Recording a thread state
/// Pins what the Security Extension keeps of a `remote_thread_create` event's `es_thread_state_t`: the flavor, and a
/// bounded copy of the state's bytes in base64 that follows eslogger's `es_token_t` rule (`nil` for a `NULL` `data`,
/// `""` when empty), and how a thread state is written: eslogger's `{flavor, state: null}` plus `state_base64`.
final class ThreadStateTests: XCTestCase {
    /// A message that owns a test's thread state bytes until the test ends.
    ///
    /// - Returns: The message's fixture.
    private func fixture() -> RawMessageFixture {
        rawMessage(type: ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE)
    }
    
    // MARK: Capture
    
    /// The flavor is kept, and the bytes are copied as base64.
    func testCopiesBytesAsBase64() {
        let state = ThreadState(from: fixture().threadState(flavor: 6, bytes: [0x00, 0x01, 0x02, 0xFF]))
        XCTAssertEqual(state.flavor, 6)
        XCTAssertEqual(state.state_base64, "AAEC/w==")
        XCTAssertEqual(state.stateBytes, Data([0x00, 0x01, 0x02, 0xFF]))
    }
    
    /// A `NULL` `data` is no bytes, whatever its size.
    func testNullDataIsNil() {
        let state = ThreadState(from: fixture().threadState(bytes: nil, size: 272))
        XCTAssertNil(state.state_base64)
        XCTAssertNil(state.stateBytes)
        XCTAssertNil(state.hexRows())
    }
    
    /// An empty state with a `data` pointer is `""`, not `nil`.
    func testEmptyStateIsEmptyString() {
        let state = ThreadState(from: fixture().threadState(bytes: []))
        XCTAssertEqual(state.state_base64, "")
        XCTAssertEqual(state.stateBytes, Data())
    }
    
    /// At most `THREAD_STATE_MAX` 32-bit words are copied: the first 5,184 bytes.
    func testCopyIsBounded() {
        XCTAssertEqual(ThreadState.maxStateSize, 5_184)
        let bytes = RawMessageFixture.bytes(ThreadState.maxStateSize + 64)
        let state = ThreadState(from: fixture().threadState(bytes: bytes))
        XCTAssertEqual(state.stateBytes, Data(bytes.prefix(ThreadState.maxStateSize)))
    }
    
    /// A size of `SIZE_MAX`, which imports as -1, is clamped rather than trapping.
    func testHugeSizeIsClamped() {
        let bytes = RawMessageFixture.bytes(ThreadState.maxStateSize)
        let state = ThreadState(from: fixture().threadState(bytes: bytes, size: Int(bitPattern: UInt.max)))
        XCTAssertEqual(state.stateBytes, Data(bytes))
    }
    
    /// The bytes are copied: changing the message's memory afterwards doesn't change them.
    ///
    /// - Throws: An `XCTest` failure if the state has no bytes.
    func testCopyOutlivesMessageMemory() throws {
        let threadState = fixture().threadState(bytes: [1, 2, 3, 4])
        let state = ThreadState(from: threadState)
        UnsafeMutablePointer(mutating: try XCTUnwrap(threadState.state.data)).update(repeating: 0xEE, count: 4)
        XCTAssertEqual(state.stateBytes, Data([1, 2, 3, 4]))
    }
    
    #if arch(arm64)
    /// An `ARM_THREAD_STATE64` is kept whole: its 272 bytes read back as the same registers.
    ///
    /// - Throws: An `XCTest` failure if the state has no bytes.
    func testArmThreadState64RoundTrips() throws {
        var registers = arm_thread_state64_t()
        registers.__x.0 = 0x1111
        registers.__pc = 0x1_0000_4000
        registers.__sp = 0x16F00_0000
        let bytes = withUnsafeBytes(of: registers) { Array($0) }
        let state = ThreadState(from: fixture().threadState(flavor: ARM_THREAD_STATE64, bytes: bytes))
        let copy = try XCTUnwrap(state.stateBytes)
        XCTAssertEqual(copy.count, 272)
        let read = copy.withUnsafeBytes { $0.loadUnaligned(as: arm_thread_state64_t.self) }
        XCTAssertEqual(read.__x.0, 0x1111)
        XCTAssertEqual(read.__pc, 0x1_0000_4000)
        XCTAssertEqual(read.__sp, 0x16F00_0000)
    }
    #endif
    
    // MARK: Presentation
    
    /// The hex dump has 16 bytes to a row, each row led by its offset.
    func testHexRows() {
        let state = ThreadState(from: fixture().threadState(bytes: RawMessageFixture.bytes(20)))
        XCTAssertEqual(state.hexRows(), ["0000  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", "0010  10 11 12 13"])
        XCTAssertEqual(ThreadState(flavor: 6, state_base64: "").hexRows(), [])
        XCTAssertNil(ThreadState(flavor: 6, state_base64: nil).hexRows())
    }
    
    // MARK: JSON
    
    /// A thread state is written as eslogger writes it, `state` always `null`, with the bytes in `state_base64`.
    ///
    /// - Throws: An `XCTest` failure if the JSON isn't an object.
    func testEncodesEsloggerKeysPlusBytes() throws {
        let json = ProcessHelpers.eventToJSON(value: ThreadState(flavor: 6, state_base64: "AAEC/w=="))
        XCTAssertEqual(json, #"{"flavor":6,"state":null,"state_base64":"AAEC/w=="}"#)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        XCTAssertTrue(object["state"] is NSNull)
    }
    
    /// A trace's bytes are kept to the bound the Security Extension keeps, under either key, so an opened trace's
    /// state is no larger than a captured one; that many characters that aren't base64 are no bytes.
    ///
    /// - Throws: The error decoding a thread state or reading the fixture, or an `XCTest` failure if the record holds
    ///   no thread state.
    func testDecodedBytesAreBounded() throws {
        let bytes = RawMessageFixture.bytes(ThreadState.maxStateSize + 3)
        let bounded = Data(bytes.prefix(ThreadState.maxStateSize))
        let decode = { (object: [String: Any]) in
            try JSONDecoder().decode(ThreadState.self, from: JSONSerialization.data(withJSONObject: object))
        }
        for key in ["state_base64", "state"] {
            XCTAssertEqual(try decode(["flavor": 6, key: Data(bytes).base64EncodedString()]).stateBytes, bounded, key)
        }
        XCTAssertNil(try decode(["flavor": 6, "state_base64": String(repeating: "!", count: 7_000)]).state_base64)
        XCTAssertEqual(try decode(["flavor": 6, "state_base64": "AAEC/w=="]).state_base64, "AAEC/w==")
        
        var record = try XCTUnwrap(try fixtureRecords("eslogger-remote-thread-create.jsonl").first)
        record["event"] = ["remote_thread_create": [
            "target": try XCTUnwrap(record["process"]),
            "thread_state": ["flavor": 6, "state": NSNull(), "state_base64": Data(bytes).base64EncodedString()],
        ]]
        let imported = try importRecord(record).event.remote_thread_create?.thread_state
        XCTAssertEqual(imported?.stateBytes, bounded)
    }
    
    /// No bytes are written as `null`, with the key kept.
    func testEncodesNullBytes() {
        XCTAssertEqual(ProcessHelpers.eventToJSON(value: ThreadState(flavor: 6, state_base64: nil)),
                       #"{"flavor":6,"state":null,"state_base64":null}"#)
    }
    
    /// A stored event without a thread state writes `thread_state` and `thread_state_string` as `null`.
    ///
    /// - Throws: An `XCTest` failure if the export has no `remote_thread_create` event.
    func testEventEncodesNullThreadState() throws {
        let fixture = fixture()
        fixture.remoteThreadCreate(threadState: nil)
        let event = try self.event("remote_thread_create", in: try export(Message(from: fixture.raw)))
        XCTAssertTrue(event["thread_state"] is NSNull)
        XCTAssertTrue(event["thread_state_string"] is NSNull)
    }
}
