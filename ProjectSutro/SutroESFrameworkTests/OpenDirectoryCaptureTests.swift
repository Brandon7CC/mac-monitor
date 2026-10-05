//
//  OpenDirectoryCaptureTests.swift
//  SutroESFrameworkTests
//
//  Created by Brandon Dalton on 10/4/26.
//

import XCTest
import EndpointSecurity
@testable import SutroESFramework


// MARK: - Test support
extension EventType {
    /// The Open Directory event this is, if any.
    var openDirectory: (any OpenDirectoryEvent)? {
        switch self {
        case .od_create_user(let event): event
        case .od_create_group(let event): event
        case .od_group_add(let event): event
        case .od_group_remove(let event): event
        case .od_modify_password(let event): event
        case .od_attribute_value_add(let event): event
        default: nil
        }
    }
}


// MARK: - Recording Open Directory events
/// Pins what the Security Extension records of an Open Directory event: the instigator's process (or `nil`, when
/// Endpoint Security leaves it out) and audit token, eslogger's member object and numbers, and missing strings kept
/// `nil`, with Mac Monitor's own fields derived from them.
final class OpenDirectoryCaptureTests: XCTestCase {
    /// eslogger's `instigator_token` for an instigator Endpoint Security left out, in the fixture's first record.
    private static let instigatorToken: [String: Any] = [
        "auid": 501, "euid": 0, "egid": 0, "ruid": 0, "rgid": 0, "pid": 4100, "asid": 100100, "pidversion": 9100,
    ]
    
    /// ``instigatorToken``, as `audit_token_t.toString()` writes it.
    private static let instigatorTokenString =
        "pid:4100, euid:0, ruid:0, rgid:0, egid:0, asid:100100, auid:501, pidversion:9100"
    
    /// The common fields of an event on the local node, without an instigator.
    private static let localNode: [String: Any] = [
        "error_code": 0, "node_name": "/Local/Default", "db_path": "/var/db/dslocal/nodes/Default",
        "instigator_token": instigatorToken,
    ]
    
    /// Record a message as the Security Extension does.
    ///
    /// - Parameter fixture: The message.
    /// - Returns: The message's Open Directory event.
    /// - Throws: An `XCTest` failure if it isn't one.
    private func record(_ fixture: RawMessageFixture) throws -> any OpenDirectoryEvent {
        try XCTUnwrap(Message(from: fixture.raw).event.openDirectory)
    }
    
    // MARK: Instigator
    
    /// An instigator Endpoint Security left out is `nil`, with its audit token read from `instigator_token`, for every
    /// Open Directory event.
    ///
    /// - Throws: An `XCTest` failure if an event isn't recorded as an Open Directory event.
    func testInstigatorLeftOut() throws {
        for (name, type, place) in RawMessageFixture.openDirectoryEvents {
            let fixture = rawMessage(version: 10, type: type)
            place(fixture, Self.localNode)
            let event = try record(fixture)
            XCTAssertNil(event.instigator, name)
            XCTAssertEqual(event.instigator_token?.pid, 4100, name)
            XCTAssertEqual(event.instigator_token?.pidversion, 9100, name)
            XCTAssertEqual(event.instigator_process_audit_token, Self.instigatorTokenString, name)
            XCTAssertEqual([event.instigator_process_name, event.instigator_process_path,
                            event.instigator_process_signing_id], [nil, nil, nil], name)
        }
    }
    
    /// The instigator's process is kept, and Mac Monitor's instigator fields come from it.
    ///
    /// - Throws: An `XCTest` failure if an event isn't recorded as an Open Directory event.
    func testInstigatorKept() throws {
        var object = Self.localNode
        object["instigator"] = [
            "executable": ["path": "/usr/bin/dscl"], "signing_id": "com.apple.dscl", "is_platform_binary": true,
            "audit_token": ["auid": 501, "pid": 4102, "asid": 100100, "pidversion": 9103],
        ]
        for (name, type, place) in RawMessageFixture.openDirectoryEvents {
            let fixture = rawMessage(version: 10, type: type)
            place(fixture, object)
            let event = try record(fixture)
            XCTAssertEqual(event.instigator?.executable?.path, "/usr/bin/dscl", name)
            XCTAssertEqual(event.instigator?.signing_id, "com.apple.dscl", name)
            XCTAssertEqual(event.instigator?.audit_token?.pid, 4102, name)
            XCTAssertEqual(event.instigator_token?.pid, 4100, name)
            XCTAssertEqual([event.instigator_process_name, event.instigator_process_path,
                            event.instigator_process_signing_id, event.instigator_process_audit_token],
                           ["dscl", "/usr/bin/dscl", "com.apple.dscl",
                            "pid:4102, euid:0, ruid:0, rgid:0, egid:0, asid:100100, auid:501, pidversion:9103"], name)
        }
    }
    
    /// `instigator_token` is read from message version 8, and not before: an older event ends before it.
    ///
    /// - Throws: An `XCTest` failure if an event isn't recorded as an Open Directory event.
    func testInstigatorTokenFromVersion8() throws {
        for (name, type, place) in RawMessageFixture.openDirectoryEvents {
            for version: UInt32 in [7, 8] {
                let fixture = rawMessage(version: version, type: type)
                place(fixture, Self.localNode)
                let event = try record(fixture)
                XCTAssertEqual(event.instigator_token?.pid, version >= 8 ? 4100 : nil, "\(name) v\(version)")
                XCTAssertEqual(event.instigator_process_audit_token == nil, version < 8, "\(name) v\(version)")
            }
        }
    }
    
    /// An instigator whose path is empty has an empty name, not the name of the current directory; and a `NULL` node
    /// name reads as "".
    ///
    /// - Throws: An `XCTest` failure if the event isn't recorded as an Open Directory event.
    func testInstigatorWithEmptyPath() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER)
        fixture.odEvent(\.od_create_user).pointee.instigator = fixture.process(path: "", signingID: "com.example.dscl")
        let event = try record(fixture)
        XCTAssertEqual(event.instigator_process_name, "")
        XCTAssertEqual(event.instigator_process_path, "")
        XCTAssertEqual(event.node_name, "")
    }
    
    // MARK: Strings and numbers
    
    /// A `NULL` database path is `nil` (eslogger's `null`), and an empty one "".
    ///
    /// - Throws: An `XCTest` failure if an event isn't recorded as an Open Directory event.
    func testDatabasePath() throws {
        for path in [nil, "", "/var/db/dslocal/nodes/Default"] {
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD)
            fixture.odEvent(\.od_group_add, eslogger: ["node_name": "/LDAPv3/ldap.example.com"])
                .pointee.db_path = fixture.token(path)
            let event = try record(fixture)
            XCTAssertEqual(event.db_path, path)
            XCTAssertEqual(event.node_name, "/LDAPv3/ldap.example.com")
        }
    }
    
    /// Each event's own strings.
    func testEventStrings() {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD)
        let attribute = fixture.odEvent(\.od_attribute_value_add, eslogger: Self.localNode)
        attribute.pointee.record_name = fixture.token("testuser")
        attribute.pointee.attribute_name = fixture.token("dsAttrTypeStandard:Comment")
        attribute.pointee.attribute_value = fixture.token("hello")
        let event = OpenDirectoryAttributeValueAddEvent(from: fixture.raw)
        XCTAssertEqual([event.record_name, event.attribute_name, event.attribute_value],
                       ["testuser", "dsAttrTypeStandard:Comment", "hello"])
        
        let user = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER)
        user.odEvent(\.od_create_user, eslogger: Self.localNode).pointee.user_name = user.token("testuser")
        XCTAssertEqual(OpenDirectoryCreateUserEvent(from: user.raw).user_name, "testuser")
        
        let group = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP)
        group.odEvent(\.od_create_group, eslogger: Self.localNode).pointee.group_name = group.token("testgroup")
        XCTAssertEqual(OpenDirectoryCreateGroupEvent(from: group.raw).group_name, "testgroup")
        
        let password = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD)
        let account = password.odEvent(\.od_modify_password, eslogger: Self.localNode)
        account.pointee.account_name = password.token("testmac$")
        XCTAssertEqual(OpenDirectoryModifyPasswordEvent(from: password.raw).account_name, "testmac$")
    }
    
    /// A group event's member is eslogger's object, and the name of its type Mac Monitor's `member_string`.
    func testGroupMembers() {
        let user = "0A0A0A0A-1B1B-4C2C-8D3D-00000000A001", group = "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014"
        let cases: [(type: Int, value: String?, name: String)] = [
            (0, "testuser", "ES_OD_MEMBER_TYPE_USER_NAME"), (1, user, "ES_OD_MEMBER_TYPE_USER_UUID"),
            (2, group, "ES_OD_MEMBER_TYPE_GROUP_UUID"), (7, nil, "UNKNOWN"),
        ]
        for (type, value, name) in cases {
            let expected = type == 7 ? nil : value
            let add = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD)
            add.setMember(of: add.odEvent(\.od_group_add, eslogger: Self.localNode), type: type, value: value)
            let added = OpenDirectoryGroupAddEvent(from: add.raw)
            XCTAssertEqual(added.member, OpenDirectoryMember(member_type: type, member_value: expected))
            XCTAssertEqual(added.member_string, name)
            
            let remove = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE)
            remove.setMember(of: remove.odEvent(\.od_group_remove, eslogger: Self.localNode), type: type, value: value)
            let removed = OpenDirectoryGroupRemoveEvent(from: remove.raw)
            XCTAssertEqual(removed.member, OpenDirectoryMember(member_type: type, member_value: expected))
            XCTAssertEqual(removed.member_string, name)
        }
    }
    
    /// Record and account types are eslogger's numbers, and their names Mac Monitor's `*_string` fields, including
    /// for a value the SDK doesn't define.
    func testRecordAndAccountTypes() {
        for (type, name) in [(1, "GROUP"), (0, "USER"), (5, "UNKNOWN")] {
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD)
            fixture.odEvent(\.od_attribute_value_add, eslogger: Self.localNode)
                .pointee.record_type = es_od_record_type_t(rawValue: UInt32(type))
            let event = OpenDirectoryAttributeValueAddEvent(from: fixture.raw)
            XCTAssertEqual(event.record_type, type)
            XCTAssertEqual(event.record_type_string, name)
        }
        let accountTypes = [(1, "ES_OD_ACCOUNT_TYPE_COMPUTER"), (0, "ES_OD_ACCOUNT_TYPE_USER"),
                            (9, "UNKNOWN_ACCOUNT_TYPE")]
        for (type, name) in accountTypes {
            let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD)
            fixture.odEvent(\.od_modify_password, eslogger: Self.localNode)
                .pointee.account_type = es_od_account_type_t(rawValue: UInt32(type))
            let event = OpenDirectoryModifyPasswordEvent(from: fixture.raw)
            XCTAssertEqual(event.account_type, type)
            XCTAssertEqual(event.account_type_string, name)
        }
    }
    
    /// The error code is kept, and described.
    ///
    /// - Throws: An `XCTest` failure if the event isn't recorded as an Open Directory event.
    func testErrorCode() throws {
        let fixture = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER)
        var object = Self.localNode
        object["error_code"] = 4102
        fixture.odEvent(\.od_create_user, eslogger: object)
        let event = try record(fixture)
        XCTAssertEqual(event.error_code, 4102)
        XCTAssertTrue(event.error_code_human?.hasPrefix("`kODErrorRecordAlreadyExists`") ?? false)
    }
    
    // MARK: Messages
    
    /// A group event's summary names the member by its name or UUID, and `od_group_remove` is its own event.
    func testGroupSummary() {
        let add = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD)
        let added = add.odEvent(\.od_group_add, eslogger: Self.localNode)
        added.pointee.group_name = add.token("testgroup")
        add.setMember(of: added, type: 0, value: "testuser")
        let context = Message(from: add.raw).context
        XCTAssertTrue(context?.hasSuffix("Added testuser to testgroup in /Local/Default") ?? false, "\(context ?? "")")
        
        let remove = rawMessage(type: ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE)
        let removed = remove.odEvent(\.od_group_remove, eslogger: Self.localNode)
        removed.pointee.group_name = remove.token("testgroup")
        remove.setMember(of: removed, type: 2, value: "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014")
        let message = Message(from: remove.raw)
        guard case .od_group_remove = message.event else { return XCTFail("Expected an od_group_remove event") }
        XCTAssertEqual(message.es_event_type, "ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE")
        XCTAssertTrue(message.context?.hasSuffix(
            "Removed ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014 from testgroup in /Local/Default") ?? false)
    }
}
