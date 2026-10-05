//
//  OpenDirectoryWireTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Open Directory events over XPC
/// Pins that the app reads the Open Directory events a Security Extension sends it (a `Message` as `JSONEncoder` writes
/// it), from 2.2.0's and from older ones, which named the member's, record's and account's types in place of eslogger's
/// object and numbers, and kept no instigator: the app drops an event it can't decode.
final class OpenDirectoryWireTests: XCTestCase {
    /// Open Directory events as Mac Monitor up to 2.1.0 sent and exported them.
    private static let legacyFixture = "macmonitor-2.1-od.json"
    
    /// A legacy event, as the Security Extension sent it: with its `id`.
    ///
    /// - Parameter name: The event's key, such as `od_group_add`.
    /// - Returns: The event's object.
    /// - Throws: An `XCTest` failure if the fixture has no such event.
    private func legacyEvent(_ name: String) throws -> [String: Any] {
        let events = try XCTUnwrap(try fixtureObject(Self.legacyFixture)["events"] as? [String: Any])
        var event = try XCTUnwrap(events[name] as? [String: Any], "No \(name) in \(Self.legacyFixture)")
        event["id"] = UUID().uuidString
        return event
    }
    
    /// Decode a legacy event as the app decodes the event in a `Message`.
    ///
    /// - Parameters:
    ///   - type: The event's type.
    ///   - name: The event's key.
    /// - Returns: The event.
    /// - Throws: The error decoding it.
    private func decodeLegacy<T: Decodable>(_ type: T.Type, _ name: String) throws -> T {
        try JSONDecoder().decode(type, from: try JSONSerialization.data(withJSONObject: try legacyEvent(name)))
    }
    
    /// A group event's member type name is read back as its number, without a value; an unknown one as no member.
    ///
    /// - Throws: The error decoding an event.
    func testLegacyGroupMembers() throws {
        let added = try decodeLegacy(OpenDirectoryGroupAddEvent.self, "od_group_add")
        XCTAssertEqual(added.member, OpenDirectoryMember(member_type: 1, member_value: nil))
        XCTAssertEqual(added.member_string, "ES_OD_MEMBER_TYPE_USER_UUID")
        XCTAssertEqual(added.group_name, "testgroup")
        
        let removed = try decodeLegacy(OpenDirectoryGroupRemoveEvent.self, "od_group_remove")
        XCTAssertNil(removed.member)
        XCTAssertEqual(removed.member_string, "UNKNOWN")
    }
    
    /// Record and account type names are read back as their numbers, and kept.
    ///
    /// - Throws: The error decoding an event.
    func testLegacyRecordAndAccountTypes() throws {
        let attribute = try decodeLegacy(OpenDirectoryAttributeValueAddEvent.self, "od_attribute_value_add")
        XCTAssertEqual(attribute.record_type, 1)
        XCTAssertEqual(attribute.record_type_string, "GROUP")
        XCTAssertEqual(attribute.attribute_value, "hello")
        
        let password = try decodeLegacy(OpenDirectoryModifyPasswordEvent.self, "od_modify_password")
        XCTAssertEqual(password.account_type, 1)
        XCTAssertEqual(password.account_type_string, "ES_OD_ACCOUNT_TYPE_COMPUTER")
        XCTAssertEqual(password.account_name, "testmac$")
    }
    
    /// A whole `Message` from an older Security Extension decodes (a new one's JSON with the legacy event in place),
    /// and keeps the instigator's fields it sent, without an instigator or token.
    ///
    /// - Throws: The error encoding or decoding a message, or an `XCTest` failure if one holds no OD event.
    func testLegacyMessages() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER)
        fixture.odEvent(\.od_create_user, eslogger: ["node_name": "/Local/Default"])
        let sent = try JSONEncoder().encode(Message(from: fixture.raw))
        var message = try XCTUnwrap(try JSONSerialization.jsonObject(with: sent) as? [String: Any])
        for name in RawMessageFixture.openDirectoryEvents.map(\.name) {
            message["event"] = [name: ["_0": try legacyEvent(name)]]
            let decoded = try JSONDecoder().decode(Message.self, from: JSONSerialization.data(withJSONObject: message))
            let event = try XCTUnwrap(decoded.event.openDirectory, name)
            XCTAssertNil(event.instigator, name)
            XCTAssertNil(event.instigator_token, name)
            XCTAssertNotNil(event.instigator_process_name, name)
            XCTAssertTrue(event.instigator_process_audit_token?.hasPrefix("pid:41") ?? false, name)
            XCTAssertNotNil(event.error_code_human, name)
        }
    }
    
    /// 2.2.0's Security Extension sends eslogger's fields, and the app reads them all back.
    ///
    /// - Throws: The error encoding or decoding a message, or an `XCTest` failure if a record holds no OD event.
    func testRoundTrip() throws {
        for record in try fixtureRecords("eslogger-od.jsonl") {
            let sent = capture(eslogger: record) { $0.fillODEvent(eslogger: record) }
            let received = try JSONDecoder().decode(Message.self, from: JSONEncoder().encode(sent))
            let (before, after) = try (XCTUnwrap(sent.event.openDirectory), XCTUnwrap(received.event.openDirectory))
            XCTAssertEqual(after.id, before.id)
            XCTAssertEqual(after.instigator?.executable?.path, before.instigator?.executable?.path)
            XCTAssertEqual(after.instigator_token, before.instigator_token)
            XCTAssertEqual(after.db_path, before.db_path)
            XCTAssertEqual(after.instigator_process_audit_token, before.instigator_process_audit_token)
            switch (sent.event, received.event) {
            case (.od_group_add(let before), .od_group_add(let after)):
                XCTAssertEqual(after.member, before.member)
                XCTAssertEqual(after.member_string, before.member_string)
            case (.od_group_remove(let before), .od_group_remove(let after)):
                XCTAssertEqual(after.member, before.member)
                XCTAssertEqual(after.member_string, before.member_string)
            case (.od_attribute_value_add(let before), .od_attribute_value_add(let after)):
                XCTAssertEqual(after.record_type, before.record_type)
                XCTAssertEqual(after.record_type_string, before.record_type_string)
            case (.od_modify_password(let before), .od_modify_password(let after)):
                XCTAssertEqual(after.account_type, before.account_type)
                XCTAssertEqual(after.account_type_string, before.account_type_string)
            default:
                break
            }
        }
    }
}
