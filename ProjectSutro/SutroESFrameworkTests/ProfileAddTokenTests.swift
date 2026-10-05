//
//  ProfileAddTokenTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - profile_add instigator token
/// Pins a `profile_add` event's `instigator_token`: a value in the event from message version 8 (`ESMessage.h`), so
/// eslogger writes it whether or not Endpoint Security gave the `_Nullable` instigator process.
final class ProfileAddTokenTests: XCTestCase {
    /// The instigator's process ID.
    private static let pid: Int32 = 7_777
    
    /// A captured event without its instigator keeps the instigator's token.
    ///
    /// - Throws: An `XCTest` failure if the export has no profile_add event.
    func testCapturedWithoutInstigator() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_PROFILE_ADD)
        let event = fixture.allocate(es_event_profile_add_t.self)
        event.pointee.profile = fixture.allocate(es_profile_t.self)
        event.pointee.instigator_token = RawMessageFixture.auditToken(pid: Self.pid)
        fixture.message.pointee.event.profile_add = event
        let profile = try self.event("profile_add", in: try export(Message(from: fixture.raw)))
        XCTAssertTrue(profile["instigator"] is NSNull)
        XCTAssertEqual((profile["instigator_token"] as? [String: Any])?["pid"] as? Int, Int(Self.pid))
    }
    
    /// An eslogger record without its instigator exports the token eslogger wrote.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no profile_add event.
    func testImportedWithoutInstigator() throws {
        let token = try XCTUnwrap(try fixtureObject("eslogger-exit.jsonl")["process"] as? [String: Any])["audit_token"]
        let record = try esloggerRecord("profile_add", type: 126, [
            "instigator": NSNull(), "instigator_token": token as Any, "is_update": false,
            "profile": ["identifier": "com.example.profile", "uuid": "UUID", "install_source": 1,
                        "organization": "Example", "display_name": "Example", "scope": "System"],
        ])
        let profile = try event("profile_add", in: try export(try importRecord(record)))
        XCTAssertTrue(profile["instigator"] is NSNull)
        XCTAssertEqual((profile["instigator_token"] as? [String: Any])?["pid"] as? Int, 4_242)
    }
}
