//
//  TCCModifyTokenTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/5/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - tcc_modify responsible token
/// Pins a `tcc_modify` event's `responsible_token`: `_Nullable` on its own in `ESMessage.h`, so Endpoint Security can
/// give it without the `_Nullable` responsible process, and eslogger writes it either way.
final class TCCModifyTokenTests: XCTestCase {
    /// The responsible process's ID.
    private static let pid: Int32 = 7_777
    
    /// A captured event without its responsible process keeps the responsible token.
    ///
    /// - Throws: An `XCTest` failure if the export has no tcc_modify event.
    func testCapturedWithoutResponsible() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_TCC_MODIFY)
        let event = fixture.allocate(es_event_tcc_modify_t.self)
        event.pointee.service = fixture.token("kTCCServiceCamera")
        event.pointee.identity = fixture.token("com.example.app")
        event.pointee.responsible_token = fixture.pointer(RawMessageFixture.auditToken(pid: Self.pid))
        fixture.message.pointee.event.tcc_modify = event
        let tcc = try self.event("tcc_modify", in: try export(Message(from: fixture.raw)))
        XCTAssertTrue(tcc["responsible"] is NSNull)
        XCTAssertEqual((tcc["responsible_token"] as? [String: Any])?["pid"] as? Int, Int(Self.pid))
    }
    
    /// An eslogger record without its responsible process exports the token eslogger wrote.
    ///
    /// - Throws: The error reading the record, or an `XCTest` failure if the export has no tcc_modify event.
    func testImportedWithoutResponsible() throws {
        let token = try XCTUnwrap(try fixtureObject("eslogger-exit.jsonl")["process"] as? [String: Any])["audit_token"]
        let record = try esloggerRecord("tcc_modify", type: Int(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY.rawValue), [
            "service": "kTCCServiceCamera", "identity": "com.example.app", "identity_type": 0, "update_type": 1,
            "instigator_token": token as Any, "instigator": NSNull(), "responsible_token": token as Any,
            "responsible": NSNull(), "right": 2, "reason": 3,
        ])
        let tcc = try event("tcc_modify", in: try export(try importRecord(record)))
        XCTAssertTrue(tcc["responsible"] is NSNull)
        XCTAssertEqual((tcc["responsible_token"] as? [String: Any])?["pid"] as? Int, 4_242)
    }
}
