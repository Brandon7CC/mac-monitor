//
//  EventHeaderTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
@testable import SutroESFramework


// MARK: - Event headers
/// Pins the cheap decode `macmonitor` runs on every event: decoded from the wire it's exactly the header of the whole
/// `Message`, and the fields Endpoint Security can leave out read as missing.
final class EventHeaderTests: XCTestCase {
    /// For every fixture event, the header read from the wire equals the one taken from the decoded `Message`.
    ///
    /// - Throws: The error reading a fixture, or encoding or decoding an event.
    func testTheWireHeaderIsTheMessagesHeader() throws {
        for message in try allFixtureMessages() {
            let data = try wire(message)
            let header = try JSONDecoder().decode(EventHeader.self, from: data)
            XCTAssertEqual(header, EventHeader(try JSONDecoder().decode(Message.self, from: data)))
            XCTAssertEqual(header.process.pid, message.process.pid)
            XCTAssertEqual(header.process.groupID, message.process.group_id)
            XCTAssertEqual(header.globalSequence, message.global_seq_num)
            XCTAssertEqual(header.sequence, message.seq_num)
            XCTAssertEqual(header.name, message.es_event_type)
            XCTAssertEqual(header.process.path, message.process.executable?.path)
        }
    }
    
    /// Sequence numbers, the user, the executable, the context, and the target path may be missing; the event's type,
    /// name, time, and process may not.
    ///
    /// - Throws: An `XCTest` failure if the minimal header doesn't read.
    func testWhatMayBeMissing() throws {
        let minimal = #"""
            {"event_type":9,"es_event_type":"ES_EVENT_TYPE_NOTIFY_EXEC","time":"2026-10-05T01:02:03.004005006Z",\#
            "process":{"pid":7,"group_id":7,"executable":null}}
            """#
        let header = try JSONDecoder().decode(EventHeader.self, from: Data(minimal.utf8))
        XCTAssertNil(header.sequence)
        XCTAssertNil(header.globalSequence)
        XCTAssertNil(header.process.user)
        XCTAssertNil(header.process.path)
        XCTAssertNil(header.context)
        XCTAssertNil(header.targetPath)
        for key in ["event_type", "es_event_type", "time", "process"] {
            var object = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(minimal.utf8)) as? [String: Any])
            object[key] = nil
            let data = try JSONSerialization.data(withJSONObject: object)
            XCTAssertThrowsError(try JSONDecoder().decode(EventHeader.self, from: data), key)
        }
    }
}
